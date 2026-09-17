#!/usr/bin/env node
import { createInterface } from 'node:readline/promises';
import { stdin as input, stdout as output } from 'node:process';
import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
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
  rekey,
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
  let muted = false;
  let restoreWrite = null;
  const out = output;
  if (hideInput && out._writeToOutput) {
    restoreWrite = out._writeToOutput;
    out._writeToOutput = function (str) {
      // swallow typed characters; let newlines through so the prompt reacts
      if (muted && !str.includes('\r') && !str.includes('\n')) return;
      restoreWrite.call(this, str);
    };
  }
  const rl = createInterface({ input, output: out });
  try {
    out.write(question + (hideInput ? ' (input hidden)' : '') + ' ');
    muted = true;
    const answer = await rl.question('');
    muted = false;
    return answer.trim();
  } finally {
    muted = false;
    rl.close();
    if (restoreWrite) out._writeToOutput = restoreWrite;
  }
}

function print(title, lines) {
  console.log(`\n--- ${title} ---`);
  for (const line of lines) console.log('  ' + line);
}

async function tryLoadConfig() {
  try {
    return JSON.parse(await readFile(configPath(), 'utf8'));
  } catch {
    return null;
  }
}

function mcpSnippets(serverPath, passphrase = '<your-passphrase>', { showEnv = true } = {}) {
  const envLines = showEnv
    ? [
        '  {',
        '    "mcp": {',
        '      "vaultguard": {',
        '        "type": "local",',
        `        "command": ["node", "${serverPath}"],`,
        `        "environment": { "VAULTGUARD_PASSPHRASE": "${passphrase}" }`,
        '      }',
        '    }',
        '  }',
        '',
        `Claude Code:  claude mcp add vaultguard -e VAULTGUARD_PASSPHRASE=${passphrase} -- node ${serverPath}`,
        '',
        'Cursor (project  .cursor\\mcp.json  or global  ~\\.cursor\\mcp.json):',
        '  {',
        '    "mcpServers": {',
        `      "vaultguard": { "command": "node", "args": ["${serverPath}"], "env": { "VAULTGUARD_PASSPHRASE": "${passphrase}" } }`,
        '    }',
        '  }',
      ]
    : [
        '  (your passphrase is already stored in config.json —',
        '   the repo does not need VAULTGUARD_PASSPHRASE in this setup.)',
        '',
        `  reference: claude mcp add vaultguard -- node ${serverPath}`,
      ];
  return [
    '',
    ':note: MCP config snippets  (passphrase comes from the env var — never a file)',
    '',
    'opencode (opencode.json, or the global config in ~/.config/opencode/opencode.jsonc):',
    ...envLines,
    '',
    ':alt: instead of editing configs, you can opt into a stored passphrase with',
    '      vaultguard init --store-passphrase  (convenient but weaker — see README)',
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
    if (passphrase) {
      const confirm = await prompt('Confirm passphrase:', true);
      if (confirm !== passphrase) {
        console.error('vaultguard: passphrases did not match.');
        process.exitCode = 1;
        return;
      }
    }
  }
  if (!passphrase) {
    if (flags['non-interactive']) {
      console.error('vaultguard: no passphrase. Pass --passphrase or set VAULTGUARD_PASSPHRASE.');
      process.exitCode = 1;
      return;
    }
    passphrase = await prompt('Passphrase must not be empty. Enter one:', true);
  }

  // Re-running init must not wipe already-configured security settings.
  const prev = await tryLoadConfig();
  const sec = securityDefaults();
  const cfg = {
    vaultPath,
    secretsFile: SECRETS_FILE_NAME,
    allowlist: prev?.allowlist ?? sec.allowlist,
    requireApproval: prev?.requireApproval ?? sec.requireApproval,
    audit: prev?.audit ?? sec.audit,
    allowGetSecret: prev?.allowGetSecret ?? sec.allowGetSecret,
  };
  const storeOnDisk = Boolean(flags['store-passphrase']);
  if (storeOnDisk) {
    cfg.storePassphraseOnDisk = true;
    cfg.passphrase = passphrase;
  }
  await saveConfig(cfg);

  const droppedStored = prev?.storePassphraseOnDisk && !storeOnDisk;
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
    storeOnDisk
      ? '⚠️  passphrase stored on disk in config.json (opt-in). Prefer the env var.'
      : 'passphrase is NOT stored on disk. Provide it via VAULTGUARD_PASSPHRASE.',
    droppedStored
      ? '⚠️  removed the previously stored passphrase (re-init without --store-passphrase). Use the env var now.'
      : '',
    '',
    'Add a secret (prompts for passphrase + value):',
    `  vaultguard add DB_URL`,
    '',
    'Connect an agent — copy these, then paste your passphrase into the env var:',
    ...mcpSnippets(join(__dirname, '..', 'src', 'server.mjs'), '<your-passphrase>', { showEnv: !storeOnDisk }),
  ]);
}

async function getRuntimeSettings(flags, { allowPrompt = true } = {}) {
  const settings = await resolveSettings(flags);
  if (!settings.vaultPath || !existsSync(settings.vaultPath)) {
    console.error('vaultguard: vault not configured. Run "vaultguard init".');
    return null;
  }
  let passphrase = settings.passphrase;
  if (!passphrase && allowPrompt && !flags['non-interactive']) {
    passphrase = await prompt('Passphrase:', true);
  }
  if (!passphrase) {
    console.error('vaultguard: passphrase not set. Set VAULTGUARD_PASSPHRASE or run the command interactively.');
    return null;
  }
  return { ...settings, passphrase };
}

async function cmdAdd({ flags, positional }) {
  const name = positional[0];
  if (!name) {
    console.error('usage: vaultguard add <NAME> [--value <secret>]');
    process.exitCode = 1;
    return;
  }
  const settings = await getRuntimeSettings(flags);
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
  print('next', [`  vaultguard set ${name}  (rotates in place)`, '  vaultguard list']);
  void b64;
}

async function cmdSet({ flags, positional }) {
  const name = positional[0];
  if (!name) {
    console.error('usage: vaultguard set <NAME> [--value <secret>]');
    process.exitCode = 1;
    return;
  }
  const settings = await getRuntimeSettings(flags);
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

async function cmdRekey({ flags }) {
  let oldPw = flags['old-passphrase'] || '';
  let newPw = flags['new-passphrase'] || '';
  if (!oldPw && !flags['non-interactive']) oldPw = await prompt('Current passphrase:', true);
  if (!newPw && !flags['non-interactive']) {
    newPw = await prompt('New passphrase:', true);
    const confirm = await prompt('Confirm new passphrase:', true);
    if (confirm !== newPw) {
      console.error('vaultguard: new passphrases did not match.');
      process.exitCode = 1;
      return;
    }
  }
  if (!oldPw || !newPw) {
    console.error('vaultguard: rekey needs both the old and the new passphrase.');
    process.exitCode = 1;
    return;
  }
  const settings = await resolveSettings(flags);
  if (!settings.vaultPath || !existsSync(settings.vaultPath)) {
    console.error('vaultguard: vault not configured. Run "vaultguard init".');
    process.exitCode = 1;
    return;
  }
  const names = await rekey(oldPw, newPw, settings.vaultPath);
  const prev = await tryLoadConfig();
  if (prev?.storePassphraseOnDisk) {
    await saveConfig({ ...prev, passphrase: newPw });
    console.log('~ stored passphrase in config.json updated to the new one.');
  }
  console.log(`~ re-encrypted ${names.length} secret(s): ${names.join(', ')}`);
  console.log('  → update VAULTGUARD_PASSPHRASE wherever you set it (opencode/Claude/Cursor).');
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

function passphraseStatus(p) {
  if (p) return 'set (env / flag / opt-in config)';
  return 'NOT set — provide VAULTGUARD_PASSPHRASE';
}

async function cmdMcp() {
  const settings = await resolveSettings();
  const pw = settings.passphrase ? '' : '<your-passphrase>';
  print(
    'connect vaultguard to your agents',
    mcpSnippets(join(__dirname, '..', 'src', 'server.mjs'), pw, { showEnv: !settings.passphrase }),
  );
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
    `passphrase: ${passphraseStatus(settings.passphrase)}`,
    `obsidian plugin: ${plugin ? 'installed' : settings.vaultPath && existsSync(settings.vaultPath) ? 'NOT installed' : 'n/a'}`,
    `approval: ${settings.requireApproval ? 'required for run_with_secret' : 'auto-approve (VAULTGUARD_REQUIRE_APPROVAL=0)'}`,
    `audit log: ${settings.audit ? `on → ${auditFilePath()}` : 'off'}`,
    `get_secret: ${settings.allowGetSecret ? 'enabled (opt-in)' : 'disabled (default)'}`,
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
  rekey: cmdRekey,
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
        '  vaultguard init [--vault <path>] [--passphrase <pw>] [--skip-plugin] [--store-passphrase]\n' +
        '  vaultguard add  <NAME> [--value <secret>]\n' +
        '  vaultguard set  <NAME> [--value <secret>]     # rotate value in place\n' +
        '  vaultguard rekey [--old-passphrase <pw>] [--new-passphrase <pw>]\n' +
        '  vaultguard list\n' +
        '  vaultguard audit [--lines <n>]                # tail the audit log\n' +
        '  vaultguard mcp                               # print MCP config snippets\n' +
        '  vaultguard info\n' +
        '  vaultguard test                              # crypto self-test\n' +
        '\n' +
        'passphrase:\n' +
        '  Not stored on disk by default. Provide VAULTGUARD_PASSPHRASE (or DOORMAN_PASSPHRASE)\n' +
        '  in your harness config, or type it at the prompt. Opt-in storage:\n' +
        '  vaultguard init --store-passphrase\n' +
        '\n' +
        'env:\n' +
        '  VAULTGUARD_VAULT_PATH, VAULT_PATH            vault folder\n' +
        '  VAULTGUARD_PASSPHRASE, DOORMAN_PASSPHRASE    passphrase\n' +
        '  VAULTGUARD_HOME                              config dir (default ~/.vaultguard)\n' +
        '  VAULTGUARD_REQUIRE_APPROVAL=0                auto-approve run_with_secret\n' +
        '  VAULTGUARD_AUDIT=0                           disable the audit log\n' +
        '  VAULTGUARD_ALLOW_GET_SECRET=1                enable get_secret (default: off)\n' +
        '\n' +
        'security (~/.vaultguard/config.json):\n' +
        '  allowlist.hosts    client names allowed to talk to the server ([]) = all\n' +
        '  allowlist.commands command prefixes allowed for run_with_secret ([]) = all\n' +
        '  requireApproval    false: auto-approve run_with_secret (true = ask)\n' +
        '  audit              true: every tool call appended to audit.jsonl\n' +
        '  allowGetSecret     true: enable get_secret (default: disabled so values\n' +
        '                           never reach the agent)\n',
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