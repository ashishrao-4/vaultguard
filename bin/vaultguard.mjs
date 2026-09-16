#!/usr/bin/env node
import { createInterface } from 'node:readline/promises';
import { stdin as input, stdout as output } from 'node:process';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';
import {
  resolveSettings,
  defaultVaultPath,
  saveConfig,
  configDir,
  configPath,
  secretsFilePath,
  SECRETS_FILE_NAME,
  securityDefaults,
  vaultLabel,
} from '../src/config.mjs';
import { selfTest } from '../src/crypto.mjs';
import {
  vaultExists,
  ensureSecretsFile,
  listSecretNames,
  addSecret,
  rotateSecret,
} from '../src/vault.mjs';
import { installPlugin, isPluginInstalled } from '../src/plugin-install.mjs';
import { readAudit, auditFilePath } from '../src/audit.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const VERSION = '0.1.0';

function parseArgs(argv) {
  const flags = {};
  const positional = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const eq = a.indexOf('=');
      if (eq !== -1) flags[a.slice(2, eq)] = a.slice(eq + 1);
      else if (argv[i + 1] && !argv[i + 1].startsWith('--')) {
        flags[a.slice(2)] = argv[++i];
      } else flags[a.slice(2)] = true;
    } else positional.push(a);
  }
  return { flags, positional };
}

async function prompt(question, hideInput = false) {
  const rl = createInterface({ input, output });
  try {
    const answer = await rl.question(question + (hideInput ? ' [input hidden]' : '') + ' ');
    return answer.trim();
  } finally {
    rl.close();
  }
}

function print(title, lines) {
  console.log(`\n--- ${title} ---`);
  for (const line of lines) console.log('  ' + line);
}

function mcpSnippets(serverPath) {
  return [
    '',
    ':note: MCP config snippets',
    '',
    'opencode (global  C:\\Users\\<you>\\.config\\opencode\\opencode.jsonc  or project  .opencode/):',
    '  {',
    '    "mcp": {',
    '      "vaultguard": {',
    '        "type": "local",',
    `        "command": ["node", "${serverPath}"]`,
    '      }',
    '    }',
    '  }',
    '',
    'Claude Code:  run  claude mcp add vaultguard -- node ' + serverPath,
    '',
    'Cursor (project  .cursor\\mcp.json):',
    '  {',
    '    "mcpServers": {',
    '      "vaultguard": { "command": "node", "args": ["' + serverPath + '"] }',
    '    }',
    '  }',
  ];
}

async function cmdInit({ flags }) {
  if (process.env.VAULTGUARD_SERVER === '1') return;

  let vaultPath = flags.vault || flags.path || '';
  if (!vaultPath) vaultPath = defaultVaultPath();
  if (!vaultPath || !existsSync(vaultPath)) {
    if (flags['non-interactive']) {
      console.error('vaultguard: vault path not found. Pass --vault <path>.');
      process.exitCode = 1;
      return;
    }
    vaultPath = await prompt('Obsidian vault path:' + (vaultPath ? ` [${vaultPath}]` : '')) || vaultPath;
  }
  if (!(await vaultExists(vaultPath))) {
    console.error(`vaultguard: not a readable directory: ${vaultPath}`);
    process.exitCode = 1;
    return;
  }

  let passphrase = flags.passphrase || flags.secret || '';
  if (!passphrase && !flags['non-interactive']) {
    passphrase = await prompt('Passphrase for this vault (needed to encrypt/decrypt):', true);
  }
  if (!passphrase) {
    if (flags['non-interactive']) {
      console.error('vaultguard: no passphrase. Pass --passphrase or set VAULTGUARD_PASSPHRASE.');
      process.exitCode = 1;
      return;
    }
    passphrase = await prompt('Passphrase must not be empty. Enter one:', true);
  }

  await saveConfig({ vaultPath, passphrase, secretsFile: SECRETS_FILE_NAME, ...securityDefaults() });

  const { created } = await ensureSecretsFile(vaultPath);
  const pluginResult = await installPlugin(vaultPath, { skip: flags['skip-plugin'] });

  print('vaultguard initialized', [
    `vault: ${vaultPath}`,
    `config: ${configPath()}`,
    `secrets: ${secretsFilePath(vaultPath)}${created ? ' (created)' : ' (exists)'}`,
    pluginResult.skipped
      ? 'Obsidian plugin: skipped (--skip-plugin)'
      : `Obsidian plugin: installed → ${pluginResult.targetDir}`,
    '',
    'Add a secret:',
    `  vaultguard add DB_URL  (prompts for the value)`,
    `  vaultguard add DB_URL --value "postgres://user:pass@host/db"`,
    '',
    'Then connect an agent (vaultguard mcp).',
    '',
    'NOTE: your passphrase is stored in plaintext in ~/.vaultguard/config.json.',
    'Protect that file, or keep the passphrase in VAULTGUARD_PASSPHRASE instead.',
  ]);
}

async function resolveRuntime(explicit) {
  const settings = await resolveSettings(explicit);
  if (!settings.vaultPath || !existsSync(settings.vaultPath)) {
    console.error('vaultguard: vault not configured. Run "vaultguard init".');
    process.exitCode = 1;
    return null;
  }
  if (!settings.passphrase) {
    console.error('vaultguard: passphrase not set. Run "vaultguard init" or set VAULTGUARD_PASSPHRASE.');
    process.exitCode = 1;
    return null;
  }
  return settings;
}

async function cmdAdd({ flags, positional }) {
  const name = positional[0];
  if (!name) {
    console.error('usage: vaultguard add <NAME> [--value <secret>]');
    process.exitCode = 1;
    return;
  }
  const settings = await resolveRuntime(flags);
  if (!settings) return;
  let value = flags.value || '';
  if (!value && !flags['non-interactive']) {
    value = await prompt(`Value for ${name}:`, true);
  }
  if (!value) {
    console.error(`vaultguard: empty value for ${name}. Refusing.`);
    process.exitCode = 1;
    return;
  }
  const b64 = await addSecret(name, value, settings.passphrase, settings.vaultPath);
  console.log(`+ secret "${name}" encrypted and written to ${secretsFilePath(settings.vaultPath)}`);
  print('next', [`  vaultguard add ${name} --value <new>` + '  (rotates in place)', '  vaultguard list']);
  void b64;
}

async function cmdSet({ flags, positional }) {
  const name = positional[0];
  if (!name) {
    console.error('usage: vaultguard set <NAME> [--value <secret>]');
    process.exitCode = 1;
    return;
  }
  const settings = await resolveRuntime(flags);
  if (!settings) return;
  let value = flags.value || '';
  if (!value && !flags['non-interactive']) value = await prompt(`New value for ${name}:`, true);
  if (!value) {
    console.error('vaultguard: empty value. Refusing.');
    process.exitCode = 1;
    return;
  }
  await rotateSecret(name, value, settings.passphrase, settings.vaultPath);
  console.log(`~ secret "${name}" rotated.`);
}

async function cmdList({ flags }) {
  const settings = await resolveSettings(flags);
  if (!settings.vaultPath || !existsSync(settings.vaultPath)) {
    console.error('vaultguard: vault not configured. Run "vaultguard init".');
    process.exitCode = 1;
    return;
  }
  const names = await listSecretNames(settings.vaultPath, settings.secretsFile);
  if (names.length === 0) console.log('(no secrets yet)');
  else console.log(names.join('\n'));
}

async function cmdMcp() {
  const settings = await resolveSettings();
  print('connect vaultguard to your agents', mcpSnippets(join(__dirname, '..', 'src', 'server.mjs')));
  if (!settings.vaultPath) console.log('\n  (tip: run "vaultguard init" first so the server finds your vault)');
}

async function cmdTest() {
  const ok = selfTest();
  console.log(ok ? 'crypto self-test: PASS' : 'crypto self-test: FAIL');
  if (!ok) process.exitCode = 1;
}

async function cmdInfo() {
  const settings = await resolveSettings();
  const plugin = settings.vaultPath ? await isPluginInstalled(settings.vaultPath) : false;
  print('vaultguard', [
    `version: ${VERSION}`,
    `config dir: ${configDir()}`,
    `config file: ${configPath()}`,
    `vault: ${settings.vaultPath || '(unset)'}`,
    `passphrase: ${settings.passphrase ? 'set' : '(unset)'}`,
    `obsidian plugin: ${plugin ? 'installed' : settings.vaultPath && existsSync(settings.vaultPath) ? 'NOT installed' : 'n/a'}`,
    `approval: ${settings.requireApproval ? 'required for run_with_secret' : 'auto-approve (VAULTGUARD_REQUIRE_APPROVAL=0)'}`,
    `audit log: ${settings.audit ? `on → ${auditFilePath()}` : 'off'}`,
    `allowed hosts: ${settings.allowlist.hosts.length ? settings.allowlist.hosts.join(', ') : '(all)'}`,
    `allowed commands: ${settings.allowlist.commands.length ? settings.allowlist.commands.join(', ') : '(all)'}`,
  ]);
}

async function cmdAudit({ flags }) {
  const entries = await readAudit(Number(flags.lines) || 50);
  if (entries.length === 0) {
    console.log('(audit log is empty)');
    return;
  }
  for (const e of entries) {
    const tool = e.tool || e.raw || '?';
    const outcome = e.outcome ?? '';
    const detail = e.secret ? ` secret=${e.secret}` : e.secrets ? ` secrets=${e.secrets.join(',')}` : '';
    const cmd = e.command ? ` cmd="${e.command.slice(0, 60)}"` : '';
    console.log(`${e.ts ?? '-'}  ${tool.padEnd(13)} ${String(outcome).padEnd(18)} host=${e.host ?? '-'}${detail}${cmd}`);
  }
}

const COMMANDS = {
  init: cmdInit,
  add: cmdAdd,
  set: cmdSet,
  list: cmdList,
  mcp: cmdMcp,
  audit: cmdAudit,
  test: cmdTest,
  info: cmdInfo,
  help() {
    console.log(
      'vaultguard — an Obsidian vault, guarded for your AI agents.\n' +
        '\n' +
        'usage:\n' +
        '  vaultguard init [--vault <path>] [--passphrase <pw>] [--skip-plugin]\n' +
        '  vaultguard add  <NAME> [--value <secret>]\n' +
        '  vaultguard set  <NAME> [--value <secret>]     # rotate in place\n' +
        '  vaultguard list\n' +
        '  vaultguard audit [--lines <n>]                # tail the audit log\n' +
        '  vaultguard mcp                               # print MCP config snippets\n' +
        '  vaultguard info\n' +
        '  vaultguard test                              # crypto self-test\n' +
        '\n' +
        'env:\n' +
        '  VAULTGUARD_VAULT_PATH, VAULT_PATH            vault folder\n' +
        '  VAULTGUARD_PASSPHRASE, DOORMAN_PASSPHRASE    passphrase\n' +
        '  VAULTGUARD_HOME                              config dir (default ~/.vaultguard)\n' +
        '  VAULTGUARD_REQUIRE_APPROVAL=0                auto-approve run_with_secret\n' +
        '  VAULTGUARD_AUDIT=0                           disable the audit log\n' +
        '\n' +
        'security (~/.vaultguard/config.json):\n' +
        '  allowlist.hosts    client names allowed to talk to the server ([]) = all\n' +
        '  allowlist.commands command prefixes allowed for run_with_secret ([]) = all\n' +
        '  requireApproval    true: run_with_secret blocked unless approved "false"\n' +
        '  audit              true: every tool call appended to audit.jsonl\n',
    );
  },
};

const { flags, positional } = parseArgs(process.argv.slice(2));
const command = positional.shift() ?? 'help';
const fn = COMMANDS[command];
if (typeof fn !== 'function') {
  console.error(`vaultguard: unknown command "${command}". Try "vaultguard help".`);
  process.exitCode = 1;
} else {
  fn({ flags, positional }).catch((err) => {
    console.error(`vaultguard: ${err.message || err}`);
    process.exitCode = 1;
  });
}