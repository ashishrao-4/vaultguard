import { readFile, writeFile, rename, access, unlink } from 'node:fs/promises';
import { constants } from 'node:fs';
import { encrypt, decrypt } from './crypto.mjs';
import { secretsFilePath } from './config.mjs';

export const BLOCK_RE = /^```secret-lock\s+(\S+?)\s*\n([\s\S]*?)\n```/gm;
const BLOCK_SRC = BLOCK_RE.source;

let tmpCounter = 0;

async function writeAtomic(file, content) {
  const tmp = `${file}.${process.pid}.${Date.now()}.${tmpCounter++}.tmp`;
  try {
    await writeFile(tmp, content, 'utf8');
    await rename(tmp, file);
  } catch (err) {
    try {
      await unlink(tmp);
    } catch {
      /* best effort */
    }
    throw err;
  }
}

function blockFor(name, b64) {
  return `\`\`\`secret-lock ${name}\n${b64}\n\`\`\``;
}

// Walk every block in `text`; for each, call fn(name, payload). If fn returns a
// string that string replaces the block; if it returns null the block is kept.
function replaceBlocks(text, fn) {
  let out = '';
  let last = 0;
  let matched = 0;
  for (const m of text.matchAll(new RegExp(BLOCK_SRC, 'gm'))) {
    const replacement = fn(m[1], m[2]);
    if (replacement == null) continue;
    out += text.slice(last, m.index) + replacement;
    last = m.index + m[0].length;
    matched++;
  }
  out += text.slice(last);
  return { out, matched };
}

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
  const block = `\n${blockFor(name, b64)}\n`;
  await writeAtomic(secretsFilePath(vaultPath), text + block);
  return b64;
}

export async function rotateSecret(name, value, passphrase, vaultPath) {
  const file = secretsFilePath(vaultPath);
  const text = await readFile(file, 'utf8');
  if (!parseSecrets(text).has(name)) {
    throw new Error(`Secret "${name}" not found.`);
  }
  const b64 = encrypt(value, passphrase);
  const { out, matched } = replaceBlocks(text, (n) => (n === name ? blockFor(name, b64) : null));
  if (!matched) throw new Error(`Secret "${name}" not found.`);
  await writeAtomic(file, out);
  return b64;
}

export async function rekey(oldPassphrase, newPassphrase, vaultPath) {
  const file = secretsFilePath(vaultPath);
  const text = await readFile(file, 'utf8');
  const names = [];
  let out = '';
  let last = 0;
  let any = false;
  for (const m of text.matchAll(new RegExp(BLOCK_SRC, 'gm'))) {
    let plain;
    try {
      plain = decrypt(m[2], oldPassphrase);
    } catch {
      throw new Error(
        `decrypt failed for "${m[1]}" with the old passphrase — nothing was changed.`,
      );
    }
    out += text.slice(last, m.index) + blockFor(m[1], encrypt(plain, newPassphrase));
    last = m.index + m[0].length;
    names.push(m[1]);
    any = true;
  }
  if (!any) {
    throw new Error('no secrets to re-encrypt.');
  }
  out += text.slice(last);
  await writeAtomic(file, out);
  return [...new Set(names)];
}