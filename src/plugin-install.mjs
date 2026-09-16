import { mkdir, writeFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { pluginInstallPath } from './config.mjs';

const RELEASES_BASE =
  'https://github.com/vnrtmnv/obsidian-inline-secret-block/releases/latest/download';
const FILES = ['main.js', 'manifest.json', 'styles.css'];

export async function installPlugin(vaultPath, { skip = false } = {}) {
  if (skip) return { skipped: true };
  if (!vaultPath) throw new Error('No vault path set — cannot install plugin.');

  const targetDir = pluginInstallPath(vaultPath);
  await mkdir(targetDir, { recursive: true });

  const results = [];
  for (const file of FILES) {
    const res = await fetch(`${RELEASES_BASE}/${file}`);
    if (!res.ok) {
      throw new Error(`Failed to download ${file} (HTTP ${res.status})`);
    }
    const bytes = Buffer.from(await res.arrayBuffer());
    await writeFile(join(targetDir, file), bytes);
    results.push(`${file}: ${bytes.length} bytes`);
  }

  return { skipped: false, targetDir, files: results };
}

export async function isPluginInstalled(vaultPath) {
  try {
    const existing = await readdir(pluginInstallPath(vaultPath));
    return FILES.every((f) => existing.includes(f));
  } catch {
    return false;
  }
}