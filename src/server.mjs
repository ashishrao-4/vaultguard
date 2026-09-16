import readline from 'node:readline';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { decrypt } from './crypto.mjs';
import { resolveSettings, vaultLabel } from './config.mjs';
import { readSecretsText, parseSecrets } from './vault.mjs';

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

let settingsCache = null;
async function getSettings() {
  if (!settingsCache) settingsCache = await resolveSettings();
  return settingsCache;
}

async function loadSecrets() {
  const { vaultPath } = await getSettings();
  const text = await readSecretsText(vaultPath);
  return parseSecrets(text ?? '');
}

function errorObject(message) {
  return { isError: true, content: [{ type: 'text', text: `Error: ${message}` }] };
}

function success(text) {
  return { content: [{ type: 'text', text }] };
}

let approveCountdown = 0;
async function awaitApproval(label) {
  if (process.env.VAULTGUARD_NO_APPROVAL === '1' || process.env.VAULTGUARD_NONSTOP) {
    return true;
  }
  if (approveCountdown > 0) {
    approveCountdown -= 1;
    return true;
  }
  if (process.stdin.isTTY) {
    const rl = readline.createInterface({ input: process.stdin, output: process.stderr });
    await new Promise((resolve) => {
      rl.question(`vaultguard: allow "${label}"? [y]es / [a]lways for this run / [n]o: `, (ans) => {
        const a = ans.trim().toLowerCase();
        if (a === 'a') approveCountdown = 50;
        rl.close();
        resolve(a === 'y' || a === 'a');
      });
    });
    return true;
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

async function handleToolsCall(params) {
  const { name, arguments: args } = params;
  const secrets = await loadSecrets();

  switch (name) {
    case 'list_secrets': {
      const names = [...secrets.keys()];
      return success(
        (names.length ? names.join('\n') : '(no secrets yet)') +
          `\n\n(${names.length} secret${names.length === 1 ? '' : 's'})`,
      );
    }

    case 'get_secret': {
      const { name: secretName } = args;
      if (!secrets.has(secretName)) {
        return errorObject(`secret "${secretName}" not found. Run list_secrets to see available names.`);
      }
      const { passphrase } = await getSettings();
      if (!passphrase) {
        return errorObject('passphrase not configured. Set VAULTGUARD_PASSPHRASE or run "vaultguard init".');
      }
      try {
        return success(decrypt(secrets.get(secretName), passphrase));
      } catch (err) {
        return errorObject(`failed to decrypt "${secretName}": ${err.message}`);
      }
    }

    case 'run_with_secret': {
      const { command, secrets: names } = args;
      if (!Array.isArray(names) || names.length === 0) {
        return errorObject('secrets: must provide at least one secret name.');
      }
      const { passphrase } = await getSettings();
      if (!passphrase) {
        return errorObject('passphrase not configured. Set VAULTGUARD_PASSPHRASE or run "vaultguard init".');
      }
      const env = { ...process.env };
      for (const n of names) {
        if (!secrets.has(n)) {
          return errorObject(`secret "${n}" not found.`);
        }
        try {
          env[n] = decrypt(secrets.get(n), passphrase);
        } catch (err) {
          return errorObject(`failed to decrypt "${n}": ${err.message}`);
        }
      }
      const allowed = await awaitApproval(command);
      if (!allowed) {
        return errorObject('command rejected by user.');
      }
      const result = await runCommand(command, env);
      const mergedErr = secretScrub(String(result.out) + String(result.err), env, names);
      if (result.code === 0) {
        return success(mergedErr || '(exit 0, no output)');
      }
      return errorObject(`exit ${result.code}${result.signal ? ` (${result.signal})` : ''}\n${mergedErr}`);
    }

    default:
      return errorObject(`unknown tool "${name}"`);
  }
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

const sink = {
  handleRequest: async (request) => {
    const ctx = { jsonrpc: '2.0', id: request.id };
    try {
      switch (request.method) {
        case 'initialize':
          return { ...ctx, result: { protocolVersion: PROTOCOL_VERSION, capabilities: { tools: {} }, serverInfo: { name: 'vaultguard', version: '0.1.0' } } };
        case 'notifications/initialized':
          return null;
        case 'tools/list':
          return { ...ctx, result: { tools: TOOLS } };
        case 'tools/call':
          return { ...ctx, result: await handleToolsCall(request.params) };
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
  const settings = await getSettings();
  process.stderr.write(`vaultguard MCP server ready • vault: ${vaultLabel(settings.vaultPath || '(unset)')}\n`);
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