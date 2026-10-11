import { randomBytes } from 'node:crypto';
import { argon2id, argon2Verify } from 'hash-wasm';

/** OWASP minimum for argon2id is m=19 MiB, t=2; we keep the node-argon2 defaults (64 MiB, t=3, p=4) for compatibility. */
const PARAMS = { memorySize: 65536, iterations: 3, parallelism: 4, hashLength: 32 } as const;
export const MIN_PASSWORD_LENGTH = 8;

export const hashPassword = (password: string) =>
  argon2id({ password, salt: randomBytes(16), ...PARAMS, outputType: 'encoded' });

/** Verifies PHC-encoded argon2 hashes (including the ones produced by node-argon2). */
export async function verifyPassword(hash: string | null | undefined, password: string): Promise<boolean> {
  if (!hash || !hash.startsWith('$argon2')) return false;
  try {
    return await argon2Verify({ password, hash });
  } catch {
    return false;
  }
}

/** A constant-cost check for unknown accounts, so timing does not reveal which e-mails exist. */
let dummy: Promise<string> | undefined;
export async function burnPasswordCheck(password: string) {
  dummy ??= hashPassword(randomBytes(8).toString('hex'));
  await verifyPassword(await dummy, password);
}

export function passwordProblem(password: string): string | null {
  if (password.length < MIN_PASSWORD_LENGTH) return 'too_short';
  if (password.length > 256) return 'too_long';
  return null;
}
