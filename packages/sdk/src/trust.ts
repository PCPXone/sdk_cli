// PCPX Access-Request / Approved-Access-Package.
//
// SDK-EXTRAKTION (Masterplan Schritt 2): unveraendert aus
// src/crypto/access-request.ts uebernommen. Zusaetzlich liegt hier jetzt
// importRecipientPublicKey und das Key-Splitting aus src/crypto/pcpx-v2.ts —
// beides reine WebCrypto-Logik ohne DOM-Bezug. Die geraetelokale
// Schluesselhaltung (IndexedDB) bleibt bewusst im Frontend.
//
// Beim Freigeben verschlüsselt der Absender das accessSecret (zweite Schlüsselhälfte)
// für den Public Key des Empfängers (ECIES-Stil: ephemeres ECDH + AES-GCM).
// Der Server speichert nur dieses verschlüsselte Paket – nie das accessSecret im Klartext.
//
// Härtung ggü. Original (Audit 2026-07-22):
//  - ECDH lieferte den AES-Schlüssel bisher direkt über `deriveKey`, also aus der
//    rohen X-Koordinate ohne KDF und ohne Kontextbindung. Jetzt: `deriveBits` +
//    HKDF-SHA256, mit noteId, recipientKeyId und BEIDEN Public Keys im `info`-Feld.
//    Damit ist ein Paket kryptografisch an genau eine Note und genau ein
//    Empfängergerät gebunden (schützt gegen Key-Substitution / Unknown-Key-Share).
//  - Das AAD des AES-GCM bindet denselben Kontext zusätzlich mit.
//  - Neu: `publicKeyFingerprint()` für einen Out-of-Band-Abgleich (siehe unten).
//    Wird in der Oberfläche auf BEIDEN Seiten angezeigt: `TrustKeyRequiredView`
//    zeigt dem Empfänger den Fingerprint seines eigenen Schlüssels,
//    `AccessRequestsPanel` zeigt dem Absender den der eingegangenen Anfrage.
//
// VERBLEIBENDE DESIGN-GRENZE (bewusst dokumentiert, nicht im Code lösbar):
// Der Absender erhält `recipientPublicKeyJwk` vom SERVER. Ein bösartiger Server
// könnte hier seinen eigenen Schlüssel unterschieben und so das accessSecret
// erhalten. Er bräuchte zusätzlich den linkSecret aus dem URL-Fragment, das er
// nie zu sehen bekommt — der Angriff senkt die Sicherheit also auf das Niveau
// eines normalen Links, hebt sie aber nicht auf. Wer die volle Zusage des
// Trust-Modus braucht, muss den Fingerprint out-of-band vergleichen.

import { bytesToBase64, base64ToBytes } from './base64.ts';

export type AccessRequest = {
  requestId: string;
  noteId: string;
  recipientKeyId: string;
  recipientPublicKeyJwk: JsonWebKey;
  deviceHint: string;
  createdAt: number;
  status: 'pending' | 'approved' | 'denied';
};

export type ApprovedAccessPackage = {
  version: 'PCPX-ACCESS-v2';
  requestId: string;
  noteId: string;
  recipientKeyId: string;
  encryptedAccessKey: string; // JSON: SealedBox
  algorithm: string;
  createdAt: number;
};

const ALGORITHM = 'ECDH-P256+HKDF-SHA256+AES-GCM-256';
const ECDH_PARAMS: EcKeyGenParams = { name: 'ECDH', namedCurve: 'P-256' };
const SHARED_SECRET_BITS = 256;

function validatePublicJwk(jwk: JsonWebKey): void {
  if (!jwk || jwk.kty !== 'EC' || jwk.crv !== 'P-256' || jwk.d !== undefined || typeof jwk.x !== 'string' || typeof jwk.y !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(jwk.x) || !/^[A-Za-z0-9_-]{43}$/.test(jwk.y)) throw new Error('Ungültiger öffentlicher Schlüssel.');
  if (bytesToBase64(base64ToBytes(jwk.x)) !== jwk.x || bytesToBase64(base64ToBytes(jwk.y)) !== jwk.y) throw new Error('Nicht-kanonischer öffentlicher Schlüssel.');
}

function validateContextIds(noteId: string, recipientId: string): void {
  for (const id of [noteId, recipientId]) {
    if (typeof id !== 'string' || !id.trim() || id.length > 256 || /[\u0000-\u001f\u007f]/.test(id)) throw new Error('Ungültiger Schlüsselkontext.');
  }
}

function validateBox(box: SealedBox | { v: number; ephemeralPublicJwk: JsonWebKey; iv: string; ciphertext: string }): void {
  validatePublicJwk(box.ephemeralPublicJwk);
  if (!/^[A-Za-z0-9_-]{16}$/.test(box.iv) || !/^[A-Za-z0-9_-]{43}$/.test(box.ciphertext) || base64ToBytes(box.ciphertext).byteLength !== 32) throw new Error('Zugriffs-Paket ist beschädigt.');
}

type SealedBox = {
  v: 2;
  ephemeralPublicJwk: JsonWebKey;
  iv: string;
  ciphertext: string;
};

/** Kanonischer Kontext-String; muss auf beiden Seiten bitgleich entstehen. */
function buildContext(noteId: string, recipientKeyId: string, ephemeralJwk: JsonWebKey, recipientJwk: JsonWebKey): Uint8Array {
  const canonical = JSON.stringify([
    'PCPX-ACCESS-v2',
    noteId,
    recipientKeyId,
    ephemeralJwk.x ?? '',
    ephemeralJwk.y ?? '',
    recipientJwk.x ?? '',
    recipientJwk.y ?? '',
  ]);
  return new TextEncoder().encode(canonical);
}

/** ECDH -> HKDF-SHA256 -> AES-GCM-256. Kontext ist fest eingebunden. */
async function deriveSharedAesKey(
  privateKey: CryptoKey,
  publicKey: CryptoKey,
  context: Uint8Array,
  usage: KeyUsage[]
): Promise<CryptoKey> {
  const sharedBits = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: publicKey },
    privateKey,
    SHARED_SECRET_BITS
  );

  let hkdfKey: CryptoKey;
  try { hkdfKey = await crypto.subtle.importKey('raw', sharedBits, 'HKDF', false, ['deriveKey']); }
  finally { new Uint8Array(sharedBits).fill(0); }

  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new TextEncoder().encode('PCPX-ACCESS-v2-salt'),
      info: context as BufferSource,
    },
    hkdfKey,
    { name: 'AES-GCM', length: 256 },
    false,
    usage
  );
}

/**
 * Verschlüsselt accessSecret für den Empfänger-Public-Key.
 * Liefert den String für ApprovedAccessPackage.encryptedAccessKey.
 */
export async function sealAccessSecretForRecipient(
  recipientPublicKeyJwk: JsonWebKey,
  accessSecret: Uint8Array,
  noteId: string,
  recipientKeyId: string
): Promise<{ encryptedAccessKey: string; algorithm: string }> {
  validateContextIds(noteId, recipientKeyId);
  if (accessSecret.byteLength !== 16) throw new Error('Ungültiges Access-Secret.');
  const recipientPub = await importRecipientPublicKey(recipientPublicKeyJwk);
  const ephemeral = await crypto.subtle.generateKey(ECDH_PARAMS, false, ['deriveBits']);
  const ephemeralPublicJwk = await crypto.subtle.exportKey('jwk', ephemeral.publicKey);

  const context = buildContext(noteId, recipientKeyId, ephemeralPublicJwk, recipientPublicKeyJwk);
  const aesKey = await deriveSharedAesKey(ephemeral.privateKey, recipientPub, context, ['encrypt']);

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: context as BufferSource },
    aesKey,
    accessSecret as BufferSource
  );

  const box: SealedBox = {
    v: 2,
    ephemeralPublicJwk,
    iv: bytesToBase64(iv),
    ciphertext: bytesToBase64(new Uint8Array(ciphertext)),
  };

  return { encryptedAccessKey: JSON.stringify(box), algorithm: ALGORITHM };
}

/** Entschlüsselt das accessSecret mit dem lokalen Private Key des Empfängers. */
export async function openAccessPackage(
  privateKey: CryptoKey,
  ownPublicKeyJwk: JsonWebKey,
  pkg: ApprovedAccessPackage
): Promise<Uint8Array> {
  validateContextIds(pkg.noteId, pkg.recipientKeyId);
  if (typeof pkg.encryptedAccessKey !== 'string' || pkg.encryptedAccessKey.length > 8192 || pkg.version !== 'PCPX-ACCESS-v2' || pkg.algorithm !== ALGORITHM) throw new Error('Ungültiges Zugriffs-Paket.');
  let box: SealedBox;
  try {
    box = JSON.parse(pkg.encryptedAccessKey) as SealedBox;
  } catch {
    throw new Error('Zugriffs-Paket ist beschädigt.');
  }
  if (box?.v !== 2 || !box.ephemeralPublicJwk || typeof box.iv !== 'string' || typeof box.ciphertext !== 'string') {
    throw new Error('Zugriffs-Paket ist beschädigt.');
  }
  validateBox(box);
  validatePublicJwk(ownPublicKeyJwk);

  const ephemeralPub = await crypto.subtle.importKey('jwk', box.ephemeralPublicJwk, ECDH_PARAMS, false, []);
  const context = buildContext(pkg.noteId, pkg.recipientKeyId, box.ephemeralPublicJwk, ownPublicKeyJwk);
  const aesKey = await deriveSharedAesKey(privateKey, ephemeralPub, context, ['decrypt']);

  const plain = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: base64ToBytes(box.iv) as BufferSource,
      additionalData: context as BufferSource,
    },
    aesKey,
    base64ToBytes(box.ciphertext) as BufferSource
  );
  return new Uint8Array(plain);
}

/**
 * Kurzer, menschenlesbarer Fingerprint eines Public Keys (6 Gruppen à 4 Zeichen).
 * Absender und Empfänger können ihn über einen zweiten Kanal vergleichen; stimmt
 * er überein, hat der Server den Schlüssel nicht ausgetauscht.
 */
export async function publicKeyFingerprint(jwk: JsonWebKey): Promise<string> {
  validatePublicJwk(jwk);
  const canonical = JSON.stringify(['P-256', jwk.x ?? '', jwk.y ?? '']);
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical));
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // ohne I/O/0/1
  const bytes = new Uint8Array(digest);
  let out = '';
  for (let i = 0; i < 24; i++) {
    if (i > 0 && i % 4 === 0) out += '-';
    out += alphabet[bytes[i] % alphabet.length];
  }
  return out;
}

// --- aus src/crypto/trust-key.ts: reine WebCrypto-Anteile ---------------------

/** Importiert einen fremden Public Key (JWK) als ECDH-Public-CryptoKey. */
export async function importRecipientPublicKey(jwk: JsonWebKey): Promise<CryptoKey> {
  validatePublicJwk(jwk);
  return crypto.subtle.importKey('jwk', jwk, ECDH_PARAMS, false, []);
}

// --- aus src/crypto/pcpx-v2.ts: Key-Splitting des Trust-Modus ----------------

export const TRUST_LINK_SECRET_BYTES = 16;
export const TRUST_ACCESS_SECRET_BYTES = 16;

/**
 * Baut die effektive Passphrase für eine Empfänger-Freigabe-Note aus den beiden
 * Hälften. Es werden BEIDE Hälften benötigt – der linkSecret im Fragment allein
 * reicht nicht, um den Schlüssel abzuleiten.
 */
export function buildSplitPassphrase(linkSecret: Uint8Array, accessSecret: Uint8Array): string {
  if (linkSecret.byteLength !== TRUST_LINK_SECRET_BYTES || accessSecret.byteLength !== TRUST_ACCESS_SECRET_BYTES) throw new Error('Ungültige Schlüsselhälfte.');
  const combined = new Uint8Array(linkSecret.byteLength + accessSecret.byteLength);
  combined.set(linkSecret, 0);
  combined.set(accessSecret, linkSecret.byteLength);
  return bytesToBase64(combined);
}

// ---------------------------------------------------------------------------
// PCPX-ACCESS-v3 — Trust-API (Masterplan Schritt 8b)
//
// Unterschied zu v2: Im Kontext steht die stabile `deviceId` aus der
// Geraete-Registry statt der ad-hoc `recipientKeyId`. Dadurch aendert sich der
// Kontext-String und damit die Byte-Ebene — deshalb eine eigene Version. Die
// Konstruktion selbst (ECDH P-256 -> HKDF-SHA256 -> AES-GCM-256, Kontext in
// `info` UND AAD) ist unveraendert. v2 bleibt fuer bestehende Web-Freigaben.
//
// KERNPUNKT DES DESIGNS (siehe docs/TRUST-API-DESIGN.md, Abschnitt 8a):
// `expectedFingerprint` ist PFLICHT. Das SDK berechnet den Fingerprint aus dem
// gelieferten Public Key neu und versiegelt nur bei Uebereinstimmung. Wenn der
// Server pruefen wuerde, pruefte der Angreifer sich selbst.
//
// Erlaubt ist ausschliesslich das menschliche Vorlese-Format
// (6 Vierergruppen). Ein roher Hash oder ein JWK als Eingabe wird abgelehnt —
// wer den Wert aus der Serverantwort kopieren will, muss dafuer zusaetzlich
// bewusst umformatieren.

const ALGORITHM_V3 = 'PCPX-ACCESS-v3+ECDH-P256+HKDF-SHA256+AES-GCM-256';

/** Menschliches Fingerprint-Format: 6 Gruppen a 4 Zeichen, ohne I/O/0/1. */
export const FINGERPRINT_PATTERN = /^[A-HJ-NP-Z2-9]{4}(-[A-HJ-NP-Z2-9]{4}){5}$/;

export type SealedAccessV3 = {
  encryptedAccessKey: string;
  algorithm: string;
};

/** Kanonischer Kontext fuer v3. Muss auf beiden Seiten bitgleich entstehen. */
function buildContextV3(
  noteId: string,
  deviceId: string,
  ephemeralJwk: JsonWebKey,
  recipientJwk: JsonWebKey
): Uint8Array {
  const canonical = JSON.stringify([
    'PCPX-ACCESS-v3',
    noteId,
    deviceId,
    ephemeralJwk.x ?? '',
    ephemeralJwk.y ?? '',
    recipientJwk.x ?? '',
    recipientJwk.y ?? '',
  ]);
  return new TextEncoder().encode(canonical);
}

/**
 * Versiegelt das accessSecret fuer ein registriertes Empfaengergeraet.
 *
 * `expectedFingerprint` MUSS aus einer Quelle stammen, die NICHT der Server
 * ist — der Empfaenger liest ihn ueber einen zweiten Kanal vor (Telefon,
 * persoenlich). Wer ihn stattdessen aus der Serverantwort berechnet, baut
 * eine Pruefung, die nichts prueft; das laesst sich technisch nicht
 * verhindern, siehe TRUST-API-DESIGN.md Abschnitt 8a.
 *
 * @throws wenn das Format ungueltig ist oder der Fingerprint nicht passt —
 *         in beiden Faellen wird NICHTS versiegelt.
 */
export async function sealAccessSecretForDevice(
  recipientPublicKeyJwk: JsonWebKey,
  accessSecret: Uint8Array,
  noteId: string,
  deviceId: string,
  expectedFingerprint: string
): Promise<SealedAccessV3> {
  validateContextIds(noteId, deviceId);
  if (accessSecret.byteLength !== TRUST_ACCESS_SECRET_BYTES) throw new Error('Ungültiges Access-Secret.');
  if (typeof expectedFingerprint !== 'string' || !FINGERPRINT_PATTERN.test(expectedFingerprint)) {
    throw new Error(
      'expectedFingerprint fehlt oder hat das falsche Format. Erwartet werden 6 Gruppen ' +
        'a 4 Zeichen (z. B. K7M2-P9XR-T4WB-N8QH-J3VC-Z5YD) — genau so, wie der Empfaenger ' +
        'ihn dir ueber einen zweiten Kanal vorliest.'
    );
  }

  // Der eigentliche Schutz: Fingerprint aus dem GELIEFERTEN Schluessel neu
  // berechnen und gegen den erwarteten Wert stellen.
  const actual = await publicKeyFingerprint(recipientPublicKeyJwk);
  if (actual !== expectedFingerprint) {
    throw new Error(
      'Der Schluessel, den der Server geliefert hat, gehoert nicht zu dem Geraet, das du ' +
        'bestaetigt hast. Es wurde nichts freigegeben. Moegliche Ursachen: Das Geraet wurde ' +
        'rotiert, oder jemand hat den Schluessel unterwegs ausgetauscht. Fingerprint erneut ' +
        'ueber einen zweiten Kanal vergleichen.'
    );
  }

  const recipientPub = await importRecipientPublicKey(recipientPublicKeyJwk);
  const ephemeral = await crypto.subtle.generateKey(ECDH_PARAMS, false, ['deriveBits']);
  const ephemeralPublicJwk = await crypto.subtle.exportKey('jwk', ephemeral.publicKey);

  const context = buildContextV3(noteId, deviceId, ephemeralPublicJwk, recipientPublicKeyJwk);
  const aesKey = await deriveSharedAesKey(ephemeral.privateKey, recipientPub, context, ['encrypt']);

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: context as BufferSource },
    aesKey,
    accessSecret as BufferSource
  );

  const box = {
    v: 3 as const,
    ephemeralPublicJwk,
    iv: bytesToBase64(iv),
    ciphertext: bytesToBase64(new Uint8Array(ciphertext)),
  };

  return { encryptedAccessKey: JSON.stringify(box), algorithm: ALGORITHM_V3 };
}

/**
 * Oeffnet ein v3-Paket mit dem privaten Schluessel des Geraets.
 * Ein v2-Paket wird hier bewusst abgelehnt (kein stiller Downgrade).
 */
export async function openDeviceAccessPackage(
  privateKey: CryptoKey,
  ownPublicKeyJwk: JsonWebKey,
  pkg: { noteId: string; deviceId: string; encryptedAccessKey: string }
): Promise<Uint8Array> {
  validateContextIds(pkg.noteId, pkg.deviceId);
  if (typeof pkg.encryptedAccessKey !== 'string' || pkg.encryptedAccessKey.length > 8192) throw new Error('Ungültiges Zugriffs-Paket.');
  let box: { v: number; ephemeralPublicJwk: JsonWebKey; iv: string; ciphertext: string };
  try {
    box = JSON.parse(pkg.encryptedAccessKey);
  } catch {
    throw new Error('Zugriffs-Paket ist beschaedigt.');
  }
  if (box?.v !== 3 || !box.ephemeralPublicJwk || typeof box.iv !== 'string' || typeof box.ciphertext !== 'string') {
    throw new Error('Zugriffs-Paket ist beschaedigt oder hat die falsche Version.');
  }
  validateBox(box);
  validatePublicJwk(ownPublicKeyJwk);

  const ephemeralPub = await crypto.subtle.importKey('jwk', box.ephemeralPublicJwk, ECDH_PARAMS, false, []);
  const context = buildContextV3(pkg.noteId, pkg.deviceId, box.ephemeralPublicJwk, ownPublicKeyJwk);
  const aesKey = await deriveSharedAesKey(privateKey, ephemeralPub, context, ['decrypt']);

  const plain = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: base64ToBytes(box.iv) as BufferSource,
      additionalData: context as BufferSource,
    },
    aesKey,
    base64ToBytes(box.ciphertext) as BufferSource
  );
  return new Uint8Array(plain);
}
