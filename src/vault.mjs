import { readFile, writeFile, access } from 'node:fs/promises';
import { constants } from 'node:fs';
import { encrypt } from './crypto.mjs';
import { secretsFilePath } from './config.mjs';

export const BLOCK_RE = /^```secret-lock\s+(\S+?)\s*\n([\s\S]*?)\n```/gm;

export const SETUP_NOTICE =
  '# Secrets\n' +
  '\n' +
  '> Guarded by **vaultguard**. Values are encrypted with AES-256-GCM.\n' +
  '> In Obsidian, enable the **Inline Secret Block** plugin and press **Show** to reveal.\n' +
  '> Agents see only the variable names via MCP — never the values.\n';

export async function vaultExists(vaultPath) {
  if (!vaultPath) return false;
  try {
    await access(vaultPath, constants.R_OK);
    return true;
  } catch {
    return false;
  }
}

export async function readSecretsText(vaultPath, fileName) {
  const file = secretsFilePath(vaultPath);
  try {
    return await readFile(file, 'utf8');
  } catch {
    return null;
  }
}

export function parseSecrets(text) {
  const secrets = new Map();
  let m;
  while ((m = BLOCK_RE.exec(text)) !== null) {
    secrets.set(m[1], m[2]);
  }
  return secrets;
}

export async function listSecretNames(vaultPath, fileName) {
  const text = await readSecretsText(vaultPath, fileName);
  if (text == null) return [];
  return [...parseSecrets(text).keys()];
}

export async function ensureSecretsFile(vaultPath) {
  const file = secretsFilePath(vaultPath);
  try {
    await access(file);
    return { created: false };
  } catch {
    await writeFile(file, SETUP_NOTICE, 'utf8');
    return { created: true };
  }
}

export async function addSecret(name, value, passphrase, vaultPath) {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) {
    throw new Error(`Invalid secret name "${name}". Use letters, digits, underscore.`);
  }
  await ensureSecretsFile(vaultPath);
  const text = (await readSecretsText(vaultPath)) ?? '';
  if (parseSecrets(text).has(name)) {
    throw new Error(`Secret "${name}" already exists. Remove it first, or use vaultguard set to rotate.`);
  }
  const b64 = encrypt(value, passphrase);
  const block = `\n\`\`\`secret-lock ${name}\n${b64}\n\`\`\`\n`;
  await writeFile(secretsFilePath(vaultPath), text + block, 'utf8');
  return b64;
}

export async function rotateSecret(name, value, passphrase, vaultPath) {
  if (!parseSecrets((await readSecretsText(vaultPath)) ?? '').has(name)) {
    throw new Error(`Secret "${name}" not found.`);
  }
  const b64 = encrypt(value, passphrase);
  const file = secretsFilePath(vaultPath);
  const text = await readFile(file, 'utf8');
  const updated = text.replace(
    new RegExp(`^(\`\`\`secret-lock\\s+${name}\\s*\n)[\\s\\S]*?(\n\`\`\`)`, 'm'),
    `$1${b64}$2`,
  );
  await writeFile(file, updated, 'utf8');
  return b64;
}