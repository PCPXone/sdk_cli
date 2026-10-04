// Tests fuer @pcpx/sdk.
//
// Kernstueck sind die Legacy-Fixtures: Container, die mit dem Frontend-Code VOR
// der SDK-Extraktion erzeugt wurden. Laesst das SDK sie nicht mehr aufgehen,
// sind bestehende Links kaputt — das ist das harte Abnahmekriterium.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import {
  CHUNK_SIZE,
  ITERATIONS,
  MIN_ACCEPTED_ITERATIONS,
  MAX_ACCEPTED_ITERATIONS,
  base64ToBytes,
  bytesToBase64,
  buildSecretLink,
  buildLinkProof,
  buildSplitPassphrase,
  createEncryptedPayload,
  decryptFile,
  deriveKey,
  encryptFile,
  openAccessPackage,
  parseSecretFragment,
  publicKeyFingerprint,
  randomBytes,
  readContainerIterations,
  safeMimeType,
  sealAccessSecretForRecipient,
  unpackDecryptedPayload,
} from '../src/index.ts';

const here = dirname(fileURLToPath(import.meta.url));

let failures = 0;
let checks = 0;

function ok(condition: unknown, label: string): void {
  checks++;
  if (condition) {
    console.log(`PASS ${label}`);
  } else {
    failures++;
    console.error(`FAIL ${label}`);
  }
}

function eq(actual: unknown, expected: unknown, label: string): void {
  const same = Object.is(actual, expected);
  if (!same) {
    console.error(`  erwartet: ${String(expected)}`);
    console.error(`  erhalten: ${String(actual)}`);
  }
  ok(same, label);
}

async function expectThrows(fn: () => Promise<unknown>, label: string): Promise<void> {
  try {
    await fn();
    ok(false, `${label} (haette werfen muessen)`);
  } catch {
    ok(true, label);
  }
}

const enc = new TextEncoder();
const dec = new TextDecoder();

async function bytesOf(blob: Blob): Promise<Uint8Array> {
  return new Uint8Array(await blob.arrayBuffer());
}

// --- 1. Legacy-Fixtures: Alt-Container muessen aufgehen ----------------------

type Fixture = {
  name: string;
  description: string;
  passphrase: string;
  saltB64: string;
  iterations: number;
  expectedKind: 'text' | 'file';
  expectedName: string;
  expectedDeclaredType: string;
  expectedContentB64: string;
  containerB64: string;
};

const fixtureFile = JSON.parse(
  readFileSync(join(here, 'fixtures', 'legacy-containers.json'), 'utf8')
) as { fixtures: Fixture[] };

console.log(`\n--- Legacy-Fixtures (${fixtureFile.fixtures.length}) ---`);

for (const fx of fixtureFile.fixtures) {
  const container = new Blob([base64ToBytes(fx.containerB64) as BufferSource]);

  // Die Iterationszahl kommt aus dem AAD-authentifizierten Header, nicht aus
  // dem Aufrufer — genau wie im echten Entschluesselungspfad.
  const iterations = await readContainerIterations(container);
  eq(iterations, fx.iterations, `${fx.name}: Iterationszahl aus dem Header`);

  const key = await deriveKey(fx.passphrase, base64ToBytes(fx.saltB64), iterations);
  const decrypted = await decryptFile(container, key, 'payload.bin', 'application/octet-stream');
  const unpacked = await unpackDecryptedPayload(decrypted);

  eq(unpacked.kind, fx.expectedKind, `${fx.name}: kind`);
  eq(unpacked.file.name, fx.expectedName, `${fx.name}: Dateiname`);
  eq(
    unpacked.declaredType,
    safeMimeType(fx.expectedDeclaredType),
    `${fx.name}: deklarierter MIME-Typ (nach Allowlist)`
  );
  eq(
    bytesToBase64(await bytesOf(unpacked.file)),
    fx.expectedContentB64,
    `${fx.name}: Inhalt byte-identisch`
  );
}

// Falsche Passphrase muss scheitern — sonst waere die Authentisierung wirkungslos.
{
  const fx = fixtureFile.fixtures[0];
  const container = new Blob([base64ToBytes(fx.containerB64) as BufferSource]);
  const key = await deriveKey('falsche-passphrase', base64ToBytes(fx.saltB64), fx.iterations);
  await expectThrows(
    () => decryptFile(container, key, 'x.bin', 'application/octet-stream'),
    'Falsche Passphrase wird abgelehnt'
  );
}

// Manipuliertes Chiffrat muss scheitern (AES-GCM-Tag).
{
  const fx = fixtureFile.fixtures[0];
  const raw = base64ToBytes(fx.containerB64);
  raw[raw.length - 1] ^= 0xff;
  const key = await deriveKey(fx.passphrase, base64ToBytes(fx.saltB64), fx.iterations);
  await expectThrows(
    () => decryptFile(new Blob([raw as BufferSource]), key, 'x.bin', 'application/octet-stream'),
    'Manipuliertes Chiffrat wird abgelehnt'
  );
}

// --- 2. Roundtrip mit dem SDK selbst ----------------------------------------

console.log('\n--- Roundtrip ---');

{
  const content = enc.encode('Roundtrip durch das SDK — äöüß');
  const payload = createEncryptedPayload(new Blob([content as BufferSource]), {
    version: 1,
    kind: 'text',
    name: 'roundtrip.txt',
    type: 'text/plain',
    size: content.byteLength,
  });

  const salt = randomBytes(16);
  const passphrase = bytesToBase64(randomBytes(16));
  const key = await deriveKey(passphrase, salt, ITERATIONS);
  const container = await encryptFile(payload, key);

  const back = await deriveKey(passphrase, salt, await readContainerIterations(container));
  const unpacked = await unpackDecryptedPayload(
    await decryptFile(container, back, 'payload.bin', 'application/octet-stream')
  );

  eq(dec.decode(await bytesOf(unpacked.file)), dec.decode(content), 'Roundtrip: Inhalt');
  eq(unpacked.file.name, 'roundtrip.txt', 'Roundtrip: Dateiname');
  eq(unpacked.kind, 'text', 'Roundtrip: kind');
}

// Mehrere Chunks: Datei knapp ueber der Chunk-Grenze.
{
  const size = CHUNK_SIZE + 1024;
  const content = new Uint8Array(size);
  for (let i = 0; i < size; i++) content[i] = i % 251;

  const salt = randomBytes(16);
  const passphrase = bytesToBase64(randomBytes(16));
  const key = await deriveKey(passphrase, salt, ITERATIONS);
  const container = await encryptFile(new Blob([content as BufferSource]), key);
  const plain = await decryptFile(container, key, 'gross.bin', 'application/octet-stream');
  const out = await bytesOf(plain);

  eq(out.byteLength, size, 'Mehr-Chunk: Groesse');
  ok(
    out[0] === content[0] && out[size - 1] === content[size - 1] && out[CHUNK_SIZE] === content[CHUNK_SIZE],
    'Mehr-Chunk: Inhalt an Chunk-Grenze korrekt'
  );
}

// --- 3. Parameter und Grenzen ------------------------------------------------

console.log('\n--- Parameter ---');

eq(ITERATIONS, 600_000, 'PBKDF2-Iterationen fuer neue Container');
eq(MIN_ACCEPTED_ITERATIONS, 180_000, 'Untergrenze Iterationen');
eq(MAX_ACCEPTED_ITERATIONS, 4_000_000, 'Obergrenze Iterationen');
eq(CHUNK_SIZE, 5 * 1024 * 1024, 'Chunk-Groesse');

await expectThrows(
  () => deriveKey('x', randomBytes(16), MIN_ACCEPTED_ITERATIONS - 1),
  'deriveKey lehnt zu wenige Iterationen ab'
);
await expectThrows(
  () => deriveKey('x', randomBytes(16), MAX_ACCEPTED_ITERATIONS + 1),
  'deriveKey lehnt zu viele Iterationen ab'
);

// Header-Aufbau: Magic und JSON-Felder liegen unverschluesselt vorn.
{
  const key = await deriveKey('p', randomBytes(16), ITERATIONS);
  const container = await encryptFile(new Blob([enc.encode('x') as BufferSource]), key);
  const head = dec.decode((await bytesOf(container)).slice(0, 13));
  eq(head, 'PCPX1-ENC-v2\n', 'Container-Magic');
}

// MIME-Allowlist: aktive Typen werden degradiert.
eq(safeMimeType('text/html'), 'application/octet-stream', 'MIME: text/html degradiert');
eq(safeMimeType('image/svg+xml'), 'application/octet-stream', 'MIME: SVG degradiert');
eq(safeMimeType('text/plain'), 'text/plain', 'MIME: text/plain bleibt');
eq(safeMimeType('TEXT/PLAIN; charset=utf-8'), 'text/plain', 'MIME: Normalisierung');
eq(safeMimeType(undefined), 'application/octet-stream', 'MIME: Fallback');

// --- 4. Fragment und Link ----------------------------------------------------

console.log('\n--- Fragment und Link ---');

const UUID = '3f2504e0-4f89-41d3-9a0c-0305e82c3301';

{
  const parsed = parseSecretFragment(`#${UUID}:abcDEF-_123`);
  eq(parsed?.id, UUID, 'Fragment: ID');
  eq(parsed?.key, 'abcDEF-_123', 'Fragment: Key');
}

eq(parseSecretFragment(`#${UUID}:pwd`)?.key, 'pwd', 'Fragment: Passwort-Platzhalter');
eq(parseSecretFragment(''), null, 'Fragment: leer -> null');
eq(parseSecretFragment('kein-hash'), null, 'Fragment: ohne # -> null');
eq(parseSecretFragment(`#${UUID}`), null, 'Fragment: ohne Key -> null');
eq(parseSecretFragment('#nicht-uuid:key'), null, 'Fragment: ungueltige UUID -> null');
eq(parseSecretFragment(`#${UUID}:a:b`), null, 'Fragment: Extra-Segment -> null');
eq(parseSecretFragment(`#${UUID}:key&x=1`), null, 'Fragment: & -> null');
eq(parseSecretFragment(`#${UUID}:key/x`), null, 'Fragment: / -> null');

eq(
  buildSecretLink('https://pcpx.one', UUID, 'schluessel'),
  `https://pcpx.one/#${UUID}:schluessel`,
  'Link-Bau'
);

// Besitznachweis ist deterministisch und an den Praefix gebunden.
{
  const a = await buildLinkProof('abc');
  const b = await buildLinkProof('abc');
  const c = await buildLinkProof('abd');
  eq(a, b, 'Link-Proof: deterministisch');
  ok(a !== c, 'Link-Proof: unterschiedliche Keys -> unterschiedlicher Hash');
  ok(!a.includes('=') && !a.includes('+') && !a.includes('/'), 'Link-Proof: Base64url ohne Padding');
}

// --- 5. Trust-Modus ----------------------------------------------------------

console.log('\n--- Trust-Modus ---');

{
  const linkSecret = randomBytes(16);
  const accessSecret = randomBytes(16);
  const combined = buildSplitPassphrase(linkSecret, accessSecret);

  eq(combined, bytesToBase64(new Uint8Array([...linkSecret, ...accessSecret])), 'Split-Passphrase: Reihenfolge');
  ok(combined !== bytesToBase64(linkSecret), 'Split-Passphrase: linkSecret allein reicht nicht');

  // Freigabe-Paket: versiegeln und mit dem privaten Schluessel wieder oeffnen.
  const pair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
  const publicJwk = await crypto.subtle.exportKey('jwk', pair.publicKey);

  const noteId = UUID;
  const keyId = 'test-key-id';
  const sealed = await sealAccessSecretForRecipient(publicJwk, accessSecret, noteId, keyId);

  const opened = await openAccessPackage(pair.privateKey, publicJwk, {
    version: 'PCPX-ACCESS-v2',
    requestId: 'req-1',
    noteId,
    recipientKeyId: keyId,
    encryptedAccessKey: sealed.encryptedAccessKey,
    algorithm: sealed.algorithm,
    createdAt: 0,
  });

  eq(bytesToBase64(opened), bytesToBase64(accessSecret), 'Freigabe-Paket: accessSecret wiederhergestellt');
  eq(sealed.algorithm, 'ECDH-P256+HKDF-SHA256+AES-GCM-256', 'Freigabe-Paket: Algorithmus-Kennung');

  // Kontextbindung: dieselbe Box unter anderer noteId darf NICHT aufgehen.
  await expectThrows(
    () =>
      openAccessPackage(pair.privateKey, publicJwk, {
        version: 'PCPX-ACCESS-v2',
        requestId: 'req-1',
        noteId: '00000000-0000-4000-8000-000000000000',
        recipientKeyId: keyId,
        encryptedAccessKey: sealed.encryptedAccessKey,
        algorithm: sealed.algorithm,
        createdAt: 0,
      }),
    'Freigabe-Paket: an noteId gebunden'
  );

  // Fingerprint fuer den Out-of-Band-Abgleich.
  const fp = await publicKeyFingerprint(publicJwk);
  eq(fp, await publicKeyFingerprint(publicJwk), 'Fingerprint: deterministisch');
  eq(fp.length, 29, 'Fingerprint: 24 Zeichen in 6 Gruppen');
  ok(/^[A-HJ-NP-Z2-9]{4}(-[A-HJ-NP-Z2-9]{4}){5}$/.test(fp), 'Fingerprint: Alphabet ohne I/O/0/1');
}

// --- Ergebnis ----------------------------------------------------------------

console.log(`\n${checks - failures}/${checks} Pruefungen bestanden.`);
if (failures > 0) {
  console.error(`${failures} FEHLGESCHLAGEN.`);
  process.exit(1);
}
console.log('Alle SDK-Tests bestanden.');
