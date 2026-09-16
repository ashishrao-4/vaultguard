import { appendFile, mkdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { configDir } from './config.mjs';

export function auditFilePath() {
  return join(configDir(), 'audit.jsonl');
}

export async function appendAudit(entry) {
  const line = {
    ts: new Date().toISOString(),
    host: entry.host ?? process.pid,
    ...entry,
  };
  await mkdir(configDir(), { recursive: true });
  await appendFile(auditFilePath(), JSON.stringify(line) + '\n', 'utf8');
}

export async function readAudit(limit = 50) {
  let raw;
  try {
    raw = await readFile(auditFilePath(), 'utf8');
  } catch {
    return [];
  }
  const lines = raw.split('\n').filter(Boolean);
  return lines.slice(-limit).map((l) => {
    try {
      return JSON.parse(l);
    } catch {
      return { raw: l };
    }
  });
}