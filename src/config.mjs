import { homedir, platform } from 'node:os';
import { join, dirname } from 'node:path';
import { readFile, writeFile, mkdir, chmod } from 'node:fs/promises';

export const SECRETS_FILE_NAME = 'Secrets.md';
export const PLUGIN_ID = 'inline-secret-block';
let warnedStalePassphrase = false;

export function securityDefaults() {
  return {
    allowlist: { hosts: [], commands: [] },
    requireApproval: true,
    audit: true,
    allowGetSecret: false,
  };
}

function boolFromEnv(...keys) {
  for (const k of keys) {
    if (k in process.env) {
      const v = String(process.env[k]).toLowerCase();
      return v === '1' || v === 'true' || v === 'yes';
    }
  }
  return undefined;
}

export async function loadConfig() {
  try {
    const raw = await readFile(configPath(), 'utf8');
    return JSON.parse(raw);
  } catch {
    return {};
  }
}

/**
 * Resolve effective settings: explicit CLI > env > config file > defaults.
 * Accepts a map of explicit values (from CLI flags).
 */
export async function resolveSettings(explicit = {}) {
  const cfg = await loadConfig();
  const sec = securityDefaults();

  const vaultPath =
    explicit.vaultPath ??
    process.env.VAULTGUARD_VAULT_PATH ??
    process.env.VAULT_PATH ??
    cfg.vaultPath ??
    '';

  // Passphrase comes from an explicit CLI value, env, or the config file
  // ONLY when the user explicitly opted in via "storePassphraseOnDisk".
  const passphrase =
    explicit.passphrase ??
    process.env.VAULTGUARD_PASSPHRASE ??
    process.env.DOORMAN_PASSPHRASE ??
    (cfg.storePassphraseOnDisk ? cfg.passphrase ?? '' : '');

  const allowedHosts =
    explicit.allowedHosts ?? cfg.allowlist?.hosts ?? sec.allowlist.hosts;
  const allowedCommands =
    explicit.allowedCommands ?? cfg.allowlist?.commands ?? sec.allowlist.commands;

  const requireApproval =
    explicit.requireApproval ??
    boolFromEnv('VAULTGUARD_REQUIRE_APPROVAL') ??
    cfg.requireApproval ??
    sec.requireApproval;

  const audit =
    explicit.audit ?? boolFromEnv('VAULTGUARD_AUDIT') ?? cfg.audit ?? sec.audit;

  const allowGetSecret =
    explicit.allowGetSecret ??
    boolFromEnv('VAULTGUARD_ALLOW_GET_SECRET') ??
    cfg.allowGetSecret ??
    sec.allowGetSecret;

  if (cfg.passphrase && !cfg.storePassphraseOnDisk) {
    if (!warnedStalePassphrase) {
      warnedStalePassphrase = true;
      process.stderr.write(
        'vaultguard: warning — a passphrase was found in config.json but storePassphraseOnDisk is off;\n' +
          'ignoring it. Set VAULTGUARD_PASSPHRASE, or re-init with --store-passphrase if you rely on that file.\n',
      );
    }
  }

  return {
    vaultPath,
    passphrase,
    secretsFile: explicit.secretsFile ?? SECRETS_FILE_NAME,
    allowlist: { hosts: allowedHosts, commands: allowedCommands },
    requireApproval,
    audit,
    allowGetSecret,
  };
}

export function configDir() {
  if (process.env.VAULTGUARD_HOME) return process.env.VAULTGUARD_HOME;
  return join(homedir(), '.vaultguard');
}

export function configPath() {
  return join(configDir(), 'config.json');
}

export function defaultVaultPath() {
  if (platform() === 'win32') {
    return join(homedir(), 'Documents', 'Obsidian Vault');
  }
  if (platform() === 'darwin') {
    return join(homedir(), 'Documents', 'Obsidian Vault');
  }
  return '';
}

export async function saveConfig(cfg) {
  await mkdir(configDir(), { recursive: true });
  await writeFile(configPath(), JSON.stringify(cfg, null, 2) + '\n', 'utf8');
  try {
    await chmod(configPath(), 0o600);
  } catch {
    // Windows ignores POSIX modes; best effort.
  }
}

export function secretsFilePath(vaultPath) {
  return join(vaultPath, SECRETS_FILE_NAME);
}

export function pluginInstallPath(vaultPath) {
  return join(vaultPath, '.obsidian', 'plugins', PLUGIN_ID);
}

export function vaultLabel(vaultPath) {
  return dirname(vaultPath).length > 0 ? vaultPath : '(unset)';
}