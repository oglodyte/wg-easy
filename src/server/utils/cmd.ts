import childProcess from 'node:child_process';

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

export const commandTestExports = { formatCommand };
