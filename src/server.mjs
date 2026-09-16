import readline from 'node:readline';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { decrypt } from './crypto.mjs';
import { resolveSettings, vaultLabel } from './config.mjs';
import { readSecretsText, parseSecrets } from './vault.mjs';
import { appendAudit } from './audit.mjs';

const PROTOCOL_VERSION = '2024-11-05';
const TOOLS = [
  {
    name: 'list_secrets',
    description:
      'List the names of secrets available in the Obsidian vault. Returns only names, never values.',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'get_secret',
    description:
      'Decrypt and return one secret value by name. Prefer passing secrets into commands with run_with_secret instead of reading them here.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string' },
      },
      required: ['name'],
    },
  },
  {
    name: 'run_with_secret',
    description:
      'Run a shell command with secrets injected into its environment as variables. The secret values are never echoed back to the caller.',
    inputSchema: {
      type: 'object',
      properties: {
        command: { type: 'string', description: 'Command to run' },
        secrets: {
          type: 'array',
          items: { type: 'string' },
          description: 'Secret names to inject. Env var name == secret name.',
        },
      },
      required: ['command', 'secrets'],
    },
  },
];

const runtime = { clientName: '' };

function errorObject(message) {
  return { isError: true, content: [{ type: 'text', text: `Error: ${message}` }] };
}

function success(text) {
  return { content: [{ type: 'text', text }] };
}

function hostAllowed(clientName, settings) {
  const hosts = settings.allowlist.hosts;
  if (!hosts || hosts.length === 0) return true;
  const n = (clientName || '').toLowerCase();
  return hosts.some((h) => n.includes(String(h).toLowerCase()));
}

function commandAllowed(command, settings) {
  const commands = settings.allowlist.commands;
  if (!commands || commands.length === 0) return true;
  return commands.some((c) =>
    command.trim().toLowerCase().startsWith(String(c).toLowerCase()),
  );
}

async function checkApproval(label, settings) {
  if (process.env.VAULTGUARD_NO_APPROVAL === '1') return true;
  if (!settings.requireApproval) return true;
  if (process.stdin.isTTY) {
    const rl = readline.createInterface({ input: process.stdin, output: process.stderr });
    const answer = await new Promise((resolve) => {
      rl.question(`vaultguard: allow "${label}"? [y/N]: `, (ans) => {
        rl.close();
        resolve(ans.trim().toLowerCase() === 'y');
      });
    });
    return answer;
  }
  return false;
}

function runCommand(command, env) {
  const [cmd, ...args] = command.split(/\s+/);
  return new Promise((resolve) => {
    const child = spawn(cmd, args, {
      shell: true,
      env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const out = { out: '', err: '' };
    child.stdout.on('data', (d) => (out.out += d));
    child.stderr.on('data', (d) => (out.err += d));
    child.on('close', (code, signal) => {
      resolve({ code: code ?? -1, signal, ...out });
    });
  });
}

function secretScrub(text, env, names) {
  for (const n of names) {
    const value = env[n];
    if (!value || value.length === 0) continue;
    text = text.split(value).join(`[REDACTED:${n}]`);
    if (value.length >= 8) {
      text = text.split(value.slice(0, 8)).join(`[REDACTED:${n}]`);
    }
  }
  return text;
}

async function settings() {
  return resolveSettings();
}

async function audit(entry) {
  const s = await settings();
  if (!s.audit) return;
  try {
    await appendAudit({ host: runtime.clientName || 'unknown', ...entry });
  } catch {
    // Audit failures never break a request.
  }
}

async function handleToolsCall(params, s) {
  const { name, arguments: args } = params;
  const secrets = await readSecretsText(s.vaultPath);
  const parsed = parseSecrets(secrets ?? '');

  let result;
  switch (name) {
    case 'list_secrets': {
      const names = [...parsed.keys()];
      result = success(
        (names.length ? names.join('\n') : '(no secrets yet)') +
          `\n\n(${names.length} secret${names.length === 1 ? '' : 's'})`,
      );
      await audit({ tool: 'list_secrets', outcome: 'ok' });
      return result;
    }

    case 'get_secret': {
      const { name: secretName } = args;
      if (!parsed.has(secretName)) {
        result = errorObject(`secret "${secretName}" not found. Run list_secrets to see available names.`);
        await audit({ tool: 'get_secret', secret: secretName, outcome: 'error:not_found' });
        return result;
      }
      if (!s.passphrase) {
        result = errorObject('passphrase not configured. Set VAULTGUARD_PASSPHRASE or run "vaultguard init".');
        await audit({ tool: 'get_secret', secret: secretName, outcome: 'error:no_passphrase' });
        return result;
      }
      try {
        result = success(decrypt(parsed.get(secretName), s.passphrase));
        await audit({ tool: 'get_secret', secret: secretName, outcome: 'ok' });
        return result;
      } catch (err) {
        result = errorObject(`failed to decrypt "${secretName}": ${err.message}`);
        await audit({ tool: 'get_secret', secret: secretName, outcome: 'error:decrypt' });
        return result;
      }
    }

    case 'run_with_secret': {
      const { command, secrets: names } = args;
      if (!Array.isArray(names) || names.length === 0) {
        result = errorObject('secrets: must provide at least one secret name.');
        await audit({ tool: 'run_with_secret', secrets: names, outcome: 'error:no_secrets' });
        return result;
      }
      if (!commandAllowed(command, s)) {
        result = errorObject(
          `command "${command}" is not allowlisted. Add it to allowlist.commands in ${'config'} or edit ~/.vaultguard/config.json.`,
        );
        await audit({ tool: 'run_with_secret', secrets: names, command, outcome: 'denied:command' });
        return result;
      }
      for (const n of names) {
        if (!parsed.has(n)) {
          result = errorObject(`secret "${n}" not found.`);
          await audit({ tool: 'run_with_secret', secrets: names, command, outcome: `error:not_found:${n}` });
          return result;
        }
      }
      if (!(await checkApproval(command, s))) {
        result = errorObject(
          'approval required. Set requireApproval=false in ~/.vaultguard/config.json (or VAULTGUARD_REQUIRE_APPROVAL=0) to auto-approve.',
        );
        await audit({ tool: 'run_with_secret', secrets: names, command, outcome: 'denied:approval' });
        return result;
      }
      const env = { ...process.env };
      for (const n of names) {
        try {
          env[n] = decrypt(parsed.get(n), s.passphrase);
        } catch (err) {
          result = errorObject(`failed to decrypt "${n}": ${err.message}`);
          await audit({ tool: 'run_with_secret', secrets: names, command, outcome: 'error:decrypt' });
          return result;
        }
      }
      const r = await runCommand(command, env);
      const merged = secretScrub(String(r.out) + String(r.err), env, names);
      await audit({
        tool: 'run_with_secret',
        secrets: names,
        command,
        outcome: r.code === 0 ? 'ok' : `error:exit_${r.code}`,
        exitCode: r.code,
      });
      if (r.code === 0) return success(merged || '(exit 0, no output)');
      return errorObject(`exit ${r.code}${r.signal ? ` (${r.signal})` : ''}\n${merged}`);
    }

    default:
      result = errorObject(`unknown tool "${name}"`);
      await audit({ tool: name, outcome: 'error:unknown_tool' });
      return result;
  }
}

const sink = {
  handleRequest: async (request) => {
    const ctx = { jsonrpc: '2.0', id: request.id };
    try {
      switch (request.method) {
        case 'initialize': {
          const client = request.params?.clientInfo || {};
          runtime.clientName = client.name || '';
          await audit({ tool: 'initialize', outcome: 'ok', client: runtime.clientName });
          return { ...ctx, result: { protocolVersion: PROTOCOL_VERSION, capabilities: { tools: {} }, serverInfo: { name: 'vaultguard', version: '0.1.0' } } };
        }
        case 'notifications/initialized':
          return null;
        case 'tools/list': {
          const s = await settings();
          if (!hostAllowed(runtime.clientName, s)) {
            await audit({ tool: 'tools/list', outcome: 'denied:host' });
            return { ...ctx, error: { code: -32000, message: `host "${runtime.clientName || 'unknown'}" not allowed` } };
          }
          await audit({ tool: 'tools/list', outcome: 'ok' });
          return { ...ctx, result: { tools: TOOLS } };
        }
        case 'tools/call': {
          const s = await settings();
          if (!hostAllowed(runtime.clientName, s)) {
            await audit({ tool: request.params?.name || '?', outcome: 'denied:host' });
            return { ...ctx, error: { code: -32000, message: `host "${runtime.clientName || 'unknown'}" not allowed` } };
          }
          return { ...ctx, result: await handleToolsCall(request.params, s) };
        }
        case 'ping':
          return { ...ctx, result: {} };
        default:
          return { ...ctx, error: { code: -32601, message: `method not found: ${request.method}` } };
      }
    } catch (err) {
      return { ...ctx, error: { code: -32603, message: String(err.message || err) } };
    }
  },
};

async function start() {
  const s = await settings();
  process.stderr.write(
    `vaultguard MCP server ready • vault: ${vaultLabel(s.vaultPath || '(unset)')} • approval: ${s.requireApproval ? 'required' : 'auto'} • audit: ${s.audit ? 'on' : 'off'}\n`,
  );
  const rl = readline.createInterface({ input: process.stdin, terminal: false });
  rl.on('line', async (line) => {
    if (!line.trim()) return;
    let request;
    try {
      request = JSON.parse(line);
    } catch {
      process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'invalid JSON' } }) + '\n');
      return;
    }
    const response = await sink.handleRequest(request);
    if (response) process.stdout.write(JSON.stringify(response) + '\n');
  });
  rl.on('close', () => process.exit(0));
}

if (fileURLToPath(import.meta.url) === process.argv[1] || process.env.VAULTGUARD_SERVER === '1') {
  start();
}

export const __serverDir = join(dirname(fileURLToPath(import.meta.url)), '..');