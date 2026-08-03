import childProcess from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { createDebug } from 'obug';

const CMD_DEBUG = createDebug('CMD');

type CommandOptions = {
  input?: string;
  log?: boolean | string;
};

function formatCommand(executable: string, args: readonly string[]) {
  return [executable, ...args]
    .map((value) =>
      /^[A-Za-z0-9_./:=+-]+$/.test(value)
        ? value
        : JSON.stringify(value.replaceAll('\n', '\\n'))
    )
    .join(' ');
}

/** Execute one binary with an argument vector. Shell parsing is never used. */
export function execFile(
  executable: string,
  args: readonly string[] = [],
  { input, log = true }: CommandOptions = {}
) {
  if (typeof log === 'string') {
    CMD_DEBUG(`$ ${log}`);
  } else if (log) {
    CMD_DEBUG(`$ ${formatCommand(executable, args)}`);
  }

  if (process.platform !== 'linux') {
    return Promise.resolve('');
  }

  return new Promise<string>((resolve, reject) => {
    const child = childProcess.spawn(executable, [...args], {
      shell: false,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];

    child.stdout.on('data', (chunk: Buffer) => stdout.push(chunk));
    child.stderr.on('data', (chunk: Buffer) => stderr.push(chunk));
    child.once('error', reject);
    child.once('close', (code, signal) => {
      if (code === 0) {
        resolve(Buffer.concat(stdout).toString().trim());
        return;
      }

      const detail = Buffer.concat(stderr).toString().trim();
      const reason = signal ? `signal ${signal}` : `exit code ${code}`;
      reject(
        new Error(
          `${executable} failed with ${reason}${detail ? `: ${detail}` : ''}`
        )
      );
    });

    if (input !== undefined) {
      child.stdin.end(input);
    } else {
      child.stdin.end();
    }
  });
}

/**
 * Provide command input through a private, single-use file for tools that
 * require a filename and cannot safely reopen a pipe such as /dev/stdin.
 */
export async function withSecureInputFile<T>(
  input: string,
  callback: (inputPath: string) => Promise<T>
) {
  const directory = await fs.mkdtemp(
    path.join(os.tmpdir(), 'wg-easy-command-input-')
  );
  const inputPath = path.join(directory, 'input');

  try {
    await fs.chmod(directory, 0o700);
    await fs.writeFile(inputPath, input, {
      encoding: 'utf8',
      flag: 'wx',
      mode: 0o600,
    });
    return await callback(inputPath);
  } finally {
    await fs.rm(directory, { force: true, recursive: true });
  }
}

export const commandTestExports = { formatCommand };
