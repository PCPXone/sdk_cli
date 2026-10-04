// Base64url-Kodierung und Zufallswerte.
//
// Aus src/crypto.ts und src/crypto/pcpx-v2.ts uebernommen — unveraendert.
// Die Kodierung ist Base64url OHNE Padding; sie bestimmt mit, wie ein Link
// aussieht, und darf sich deshalb nicht aendern.

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function base64ToBytes(value: string): Uint8Array {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/** Erzeugt n kryptografisch sichere Zufallsbytes. */
export function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

export function randomToken(bytes = 32): string {
  return bytesToBase64(randomBytes(bytes));
}
