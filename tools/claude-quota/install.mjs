import { chmod, mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';

// Installs maintained copies outside a checkout; rerun after pulling an upgrade.
async function install(path, contents) {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = `${path}.${randomUUID()}.tmp`;
  try {
    await writeFile(temporary, contents, { mode: 0o600, flag: 'wx' });
    await chmod(temporary, 0o600);
    await rename(temporary, path);
  } finally { await rm(temporary, { force: true }); }
}

async function main() {
  if (process.argv.slice(2).some(arg => arg !== '--no-enable')) throw new Error('usage');
  const home = homedir();
  await install(join(home, '.local/share/cliproxyapi-quota/snapshot.mjs'), await readFile(new URL('./snapshot.mjs', import.meta.url)));
  // systemd quoting: escape specifiers and environment expansion in the executable path.
  const node = '"' + process.execPath.replaceAll('\\', '\\\\').replaceAll('"', '\\"').replaceAll('%', '%%').replaceAll('$', '$$') + '"';
  for (const [source, destination] of [
    ['collector.service', 'cliproxy-claude-quota.service'],
    ['collector.timer', 'cliproxy-claude-quota.timer'],
    ['health.service', 'cliproxy-claude-quota-health.service'],
    ['health.timer', 'cliproxy-claude-quota-health.timer'],
  ]) {
    const template = await readFile(new URL(`./${source}`, import.meta.url), 'utf8');
    await install(join(home, '.config/systemd/user', destination), template.replaceAll('@NODE@', node));
  }
  if (!process.argv.includes('--no-enable')) {
    for (const args of [
      ['--user', 'daemon-reload'],
      ['--user', 'enable', '--now', 'cliproxy-claude-quota.timer', 'cliproxy-claude-quota-health.timer'],
    ]) {
      const result = spawnSync('systemctl', args, { stdio: 'ignore' });
      if (result.error || result.status !== 0) throw new Error('systemd');
    }
  }
  console.log('Installed Claude quota collector and health units');
}

main().catch(() => {
  console.error('Collector installation failed; check Node, filesystem access, and the user systemd session');
  process.exitCode = 1;
});
