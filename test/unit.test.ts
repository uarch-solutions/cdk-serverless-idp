import { createHash } from 'node:crypto';
import { admin, newSigningKey } from '../runtime/admin.js';
import type { RuntimeSecret } from '../runtime/deps.js';
import { describe, expect, it } from 'vitest';
import { base32Decode, base32Encode, Cipher, hookSignature, hotp, recoveryHash, verifyTotp } from '../runtime/crypto.js';
import { profileFromIdToken } from '../runtime/federation.js';
import { sanitizeClaims } from '../runtime/hooks.js';
import { hashPassword, passwordProblem, verifyPassword } from '../runtime/passwords.js';
import { esc, page } from '../runtime/views.js';

const jwt = (claims: Record<string, unknown>) => `e30.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.sig`;

describe('crypto', () => {
  it('HOTP matches the RFC 4226 test vectors', () => {
    const secret = Buffer.from('12345678901234567890');
    expect([0, 1, 2, 9].map((c) => hotp(secret, c))).toEqual(['755224', '287082', '359152', '520489']);
  });

  it('TOTP: ±1 step, no replay at or before the last used step', () => {
    const secret = base32Encode(Buffer.from('12345678901234567890'));
    const now = new Date(59_000); // step 1
    const code = hotp(base32Decode(secret), 1);
    expect(verifyTotp(secret, code, now, null)).toBe(1);
    expect(verifyTotp(secret, code, now, 1)).toBeNull();
    expect(verifyTotp(secret, '12345', now, null)).toBeNull();
    expect(verifyTotp(secret, hotp(base32Decode(secret), 5), now, null)).toBeNull();
  });

  it('AES-GCM round trip; tampering is detected', () => {
    const c = new Cipher(Buffer.alloc(32, 7));
    const enc = c.encrypt('segredo');
    expect(c.decrypt(enc)).toBe('segredo');
    const parts = enc.split('.');
    parts[3] = Buffer.from('x').toString('base64url');
    expect(() => c.decrypt(parts.join('.'))).toThrow();
  });

  it('recovery hash is the sha256 of the trimmed lowercase code (same as the old system)', () => {
    expect(recoveryHash(' ABCDE-12345 ')).toBe(createHash('sha256').update('abcde-12345').digest('hex'));
  });

  it('hook signature is HMAC-SHA256 over "<timestamp>.<body>"', () => {
    expect(hookSignature('k', '1', '{}')).toMatch(/^sha256=[0-9a-f]{64}$/);
    expect(hookSignature('k', '1', '{}')).not.toBe(hookSignature('k', '2', '{}'));
  });
});

describe('passwords', () => {
  it('argon2id hash and verify; rejects other formats and wrong passwords', async () => {
    const h = await hashPassword('Correta-123');
    expect(h.startsWith('$argon2id$')).toBe(true);
    expect(await verifyPassword(h, 'Correta-123')).toBe(true);
    expect(await verifyPassword(h, 'errada')).toBe(false);
    expect(await verifyPassword('$2b$10$bcrypt', 'x')).toBe(false);
    expect(await verifyPassword(null, 'x')).toBe(false);
    expect(passwordProblem('1234567')).toBe('too_short');
    expect(passwordProblem('12345678')).toBeNull();
  });
});

describe('post-login hook claims', () => {
  it('keeps only the application prefix, never reserved claims; too large is refused', () => {
    expect(sanitizeClaims('app', { 'app:role': 'A', role: 'x', 'other:role': 'y', sub: 'z', 'app:n': 1 })).toEqual({ 'app:role': 'A', 'app:n': 1 });
    expect(sanitizeClaims('app', null)).toEqual({});
    expect(sanitizeClaims('app', { 'app:big': 'x'.repeat(5000) })).toBeNull();
  });
});

describe('upstream ID token', () => {
  const base = { iss: 'https://accounts.google.com', aud: 'cid', exp: 2_000_000_000, nonce: 'n1', sub: 'g-1', email: 'A@B.com', email_verified: true };
  it('checks issuer, audience, expiry and nonce', () => {
    expect(profileFromIdToken(jwt(base), { issuers: ['https://accounts.google.com'], audience: 'cid', nonce: 'n1' })).toEqual({ subject: 'g-1', email: 'a@b.com', emailVerified: true, name: null });
    for (const bad of [{ iss: 'https://evil' }, { aud: 'other' }, { exp: 1 }, { nonce: 'n2' }]) {
      expect(() => profileFromIdToken(jwt({ ...base, ...bad }), { issuers: ['https://accounts.google.com'], audience: 'cid', nonce: 'n1' })).toThrow();
    }
  });
});

describe('views', () => {
  it('escapes user content and never emits scripts', () => {
    expect(esc('<script>"&\'')).toBe('&lt;script&gt;&quot;&amp;&#39;');
    const html = page({ realm: { displayName: '<b>X</b>', branding: { color: 'red;}body{', logoUrl: 'javascript:alert(1)' } }, locale: 'en', title: 't', body: '' });
    expect(html).not.toContain('<b>X</b>');
    expect(html).not.toContain('javascript:');
    expect(html).toContain('--brand:#2563eb'); // invalid color falls back
  });
});

describe('signing keys', () => {
  const run = async (action: 'bootstrap' | 'rotateKeys', current: RuntimeSecret | null) => {
    let written: RuntimeSecret | null = null;
    const r = await admin({ action } as never, {
      secretIo: { read: async () => current, write: async (s) => { written = s; } }, secret: current, cipher: null,
    } as never);
    return { r, written: written as RuntimeSecret | null };
  };
  const old = (): RuntimeSecret => ({ jwks: { keys: [newSigningKey()] }, cookieKeys: ['a', 'b'], dataKey: 'k' });

  it('a new installation has an ES256 and an RS256 key', async () => {
    const { written } = await run('bootstrap', null);
    expect(written!.jwks.keys.map((k) => k.alg)).toEqual(['ES256', 'RS256']);
  });

  it('bootstrap adds the RS256 key to an installation made before 0.4.0, keeping its keys; then it is a no-op', async () => {
    const before = old();
    const { r, written } = await run('bootstrap', before);
    expect(r).toMatchObject({ ok: true, created: false, addedRsaKey: true });
    expect(written!.jwks.keys[0]).toEqual(before.jwks.keys[0]);
    expect(written!.jwks.keys[1]).toMatchObject({ kty: 'RSA', alg: 'RS256' });
    expect((await run('bootstrap', written)).written).toBeNull();
  });

  it('rotation makes new keys of both kinds and keeps the previous ones to verify', async () => {
    const { written: first } = await run('bootstrap', null);
    const { written } = await run('rotateKeys', first);
    expect(written!.jwks.keys.map((k) => k.alg)).toEqual(['ES256', 'RS256', 'ES256', 'RS256']);
    expect(written!.jwks.keys.slice(2)).toEqual(first!.jwks.keys);
  });
});
