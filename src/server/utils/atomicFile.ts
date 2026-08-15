import { randomUUID } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';

export async function atomicWriteFile(
  filePath: string,
  contents: string,
  validate?: (temporaryPath: string) => Promise<void>
) {
  const temporaryPath = path.join(
    path.dirname(filePath),
    `.wge-${randomUUID().slice(0, 8)}.conf`
  );
  let handle: Awaited<ReturnType<typeof fs.open>> | undefined;

  try {
    handle = await fs.open(temporaryPath, 'wx', 0o600);
    await handle.writeFile(contents, { encoding: 'utf8' });
    await handle.sync();
    await handle.close();
    handle = undefined;
    await validate?.(temporaryPath);
    await fs.rename(temporaryPath, filePath);
    await fs.chmod(filePath, 0o600);
  } catch (error) {
    await handle?.close().catch(() => {});
    await fs.unlink(temporaryPath).catch(() => {});
    throw error;
  }
}
