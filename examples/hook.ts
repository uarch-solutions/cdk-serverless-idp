// A post-login hook for an Express/Nest/Lambda backend: verify the signature, then decide.
import { createHmac, timingSafeEqual } from 'node:crypto';

export function verifyIdpHook(secret: string, headers: Record<string, string | undefined>, rawBody: string): boolean {
  const ts = headers['x-idp-timestamp'] ?? '';
  const sig = headers['x-idp-signature'] ?? '';
  if (Math.abs(Date.now() / 1000 - Number(ts)) > 300) return false; // replay window
  const expected = `sha256=${createHmac('sha256', secret).update(`${ts}.${rawBody}`).digest('hex')}`;
  return sig.length === expected.length && timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
}

// Body: { event: 'login' | 'token', realm, clientId, method?, user: { sub, email, name, emailVerified } }
export async function decide(body: { realm: string; user: { sub: string } }) {
  const member = await findMember(body.realm, body.user.sub); // your database
  if (!member || !member.active) return { allow: false, reason: 'Your access was disabled' };
  return { allow: true, claims: { 'my-saas:role': member.role, 'my-saas:plan': member.plan } };
}

declare function findMember(realm: string, sub: string): Promise<{ active: boolean; role: string; plan: string } | null>;
