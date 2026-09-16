import { fileURLToPath } from 'node:url';
import {
  pbkdf2Sync,
  createCipheriv,
  createDecipheriv,
  randomBytes,
} from 'node:crypto';

export const PBKDF2_ITERATIONS = 250_000;
export const SALT_LEN = 16;
export const IV_LEN = 12;
export const TAG_LEN = 16;

export function encrypt(plaintext, passphrase) {
  const salt = randomBytes(SALT_LEN);
  const iv = randomBytes(IV_LEN);
  const key = deriveKey(passphrase, salt);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final(),
    cipher.getAuthTag(),
  ]);
  return Buffer.concat([salt, iv, ct]).toString('base64');
}

export function decrypt(payloadB64, passphrase) {
  const payload = Buffer.from(payloadB64.trim().replace(/\s+/g, ''), 'base64');
  if (payload.length < SALT_LEN + IV_LEN + TAG_LEN) {
    throw new Error('Malformed payload: invalid base64');
  }
  const salt = payload.subarray(0, SALT_LEN);
  const iv = payload.subarray(SALT_LEN, SALT_LEN + IV_LEN);
  const ciphertext = payload.subarray(SALT_LEN + IV_LEN);
  const key = deriveKey(passphrase, salt);
  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(ciphertext.subarray(ciphertext.length - TAG_LEN));
  return Buffer.concat([
    decipher.update(ciphertext.subarray(0, ciphertext.length - TAG_LEN)),
    decipher.final(),
  ]).toString('utf8');
}

function deriveKey(passphrase, salt) {
  return pbkdf2Sync(passphrase, salt, PBKDF2_ITERATIONS, 32, 'sha256');
}

export function selfTest() {
  const value = 'vaultguard-self-test-2026';
  const b64 = encrypt(value, 'vaultguard-test');
  return decrypt(b64, 'vaultguard-test') === value;
}

if (fileURLToPath(import.meta.url) === process.argv[1]) {
  const [, , command, passphrase, input] = process.argv;
  if (command === 'encrypt' && passphrase && input) {
    process.stdout.write(encrypt(input, passphrase) + '\n');
  } else if (command === 'decrypt' && passphrase && input) {
    try {
      process.stdout.write(decrypt(input, passphrase) + '\n');
    } catch (err) {
      process.exitCode = 1;
      process.stderr.write(String(err.message) + '\n');
    }
  } else {
    process.stderr.write(
      'Usage: node src/crypto.mjs encrypt|decrypt <passphrase> <input>\n',
    );
    process.exitCode = 2;
  }
}