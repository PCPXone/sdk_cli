// Link- und Fragment-Format.
//
// Der Schluessel reist im URL-Fragment (hinter dem #). Dieser Teil einer URL
// wird vom Browser nicht an den Server uebertragen — das ist die Grundlage der
// Zero-Knowledge-Zusage. Das Format darf sich nicht aendern, sonst brechen
// bestehende Links.
//
// Format: <origin>/#<noteId>:<linkKey>
//   noteId  = UUID v4 (Serverseite)
//   linkKey = Base64url-Schluesselmaterial, oder der Literalwert 'pwd', wenn
//             der Inhalt passwortgeschuetzt ist und die Passphrase gar nicht
//             im Link steht.
//
// Uebernommen aus src/App.tsx (parseSecretHash), src/components/SecureComposer.tsx
// (Link-Bau) und src/lib/trustApi.ts (Besitznachweis).

import { bytesToBase64 } from './base64.ts';

/** Literalwert im Fragment, wenn die Passphrase NICHT im Link steht. */
export const PASSWORD_PLACEHOLDER = 'pwd';

export type FragmentParams = {
  id: string;
  key: string;
};

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Zerlegt ein URL-Fragment in Note-ID und Schluessel.
 * Liefert null, wenn das Fragment nicht dem erwarteten Format entspricht —
 * bewusst streng, damit nichts Unerwartetes in die Krypto laeuft.
 */
export function parseSecretFragment(hash: string): FragmentParams | null {
  if (!hash.startsWith('#')) return null;
  if (hash.length > 4200) return null;
  const raw = hash.slice(1).trim();
  if (!raw || raw.includes('/') || raw.includes('&')) return null;
  const [id, key, extra] = raw.split(':');
  if (!id || !key || extra) return null;
  if (!UUID_REGEX.test(id)) return null;
  if (key.length > 4096 || /[\s\u0000-\u001f\u007f]/.test(key)) return null;
  return { id, key };
}

/** Baut den vollstaendigen Teil-Link. `origin` ohne abschliessenden Schraegstrich. */
export function buildSecretLink(origin: string, id: string, linkKey: string): string {
  return `${origin}/#${id}:${linkKey}`;
}

export async function sha256Base64Url(value: string): Promise<string> {
  const data = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return bytesToBase64(new Uint8Array(digest));
}

/**
 * Besitznachweis fuer den Link.
 *
 * Der Absender hinterlegt diesen Hash bei der Erstellung, der Empfaenger schickt
 * ihn mit der Zugriffsanfrage. Nur wer das Fragment wirklich hat, kann ihn bilden.
 * Der Server lernt dabei nichts Neues — er kennt den Hash bereits, und ein
 * 128-Bit-Zufallswert ist daraus nicht rueckrechenbar.
 *
 * Beide Seiten MUESSEN diese Funktion verwenden, damit die Werte uebereinstimmen.
 */
export async function buildLinkProof(linkKey: string): Promise<string> {
  return sha256Base64Url(`pcpx-link-proof|${linkKey}`);
}
