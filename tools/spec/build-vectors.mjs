// Testvektoren fuer PCPX1-ENC-v2.
//
// Dieser Generator baut Container NICHT mit dem SDK, sondern aus der
// Spezifikation heraus — nur mit node:crypto. Das ist Absicht: wuerde er
// `encryptFile` aufrufen, pruefte der spaetere Test das SDK gegen sich selbst
// und jeder Spezifikationsfehler bliebe unsichtbar. So sind es zwei
// unabhaengige Implementierungen, und der Test in beide Richtungen
// (SDK liest Generator, Generator liest SDK) ist ein echter Abgleich.
//
// Alle Zufallswerte sind hier fest verdrahtet. Container muessen Byte fuer Byte
// reproduzierbar sein, sonst taugen sie nicht als Vektor.

import { createHash, pbkdf2Sync, createCipheriv } from 'node:crypto';
import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT = resolve(HERE, '../../tests/vectors/pcpx1-enc-v2.json');

const MAGIC = Buffer.from('PCPX1-ENC-v2\n', 'utf8');
const CHUNK_SIZE = 5 * 1024 * 1024;
const ITERATIONS = 600_000;
const IV_BYTES = 12;

const b64u = (buf) => Buffer.from(buf).toString('base64url');

/** Deterministischer Fuellinhalt: Byte i ist (i * 31 + 7) mod 256. */
function pattern(length) {
  const out = Buffer.alloc(length);
  for (let i = 0; i < length; i++) out[i] = (i * 31 + 7) & 0xff;
  return out;
}

function deriveKey(passphrase, salt, iterations) {
  return pbkdf2Sync(Buffer.from(passphrase, 'utf8'), salt, iterations, 32, 'sha256');
}

function containerHeaderBytes(payloadSize, totalChunks, iterations) {
  const header = {
    version: 2,
    alg: 'AES-GCM',
    kdf: 'PBKDF2-SHA256',
    iterations,
    chunkSize: CHUNK_SIZE,
    payloadSize,
    totalChunks,
    aad: 'PCPX1-CHUNK-AAD-v1',
  };
  // Reihenfolge der Felder ist die des SDK; JSON.stringify haelt sie ein.
  const json = Buffer.from(JSON.stringify(header), 'utf8');
  const len = Buffer.alloc(4);
  len.writeUInt32BE(json.length, 0);
  return { bytes: Buffer.concat([MAGIC, len, json]), header, json };
}

function chunkAad(containerHeader, index) {
  const idx = Buffer.alloc(4);
  idx.writeUInt32BE(index, 0);
  return Buffer.concat([containerHeader, idx]);
}

function buildContainer({ passphrase, salt, iterations, plaintext, ivs }) {
  const totalChunks = Math.max(1, Math.ceil(plaintext.length / CHUNK_SIZE));
  if (ivs.length !== totalChunks) throw new Error(`${totalChunks} IVs noetig, ${ivs.length} angegeben`);
  const { bytes: containerHeader, header } = containerHeaderBytes(plaintext.length, totalChunks, iterations);
  const key = deriveKey(passphrase, salt, iterations);

  const parts = [containerHeader];
  for (let i = 0; i < totalChunks; i++) {
    const slice = plaintext.subarray(i * CHUNK_SIZE, Math.min((i + 1) * CHUNK_SIZE, plaintext.length));
    const cipher = createCipheriv('aes-256-gcm', key, ivs[i]);
    cipher.setAAD(chunkAad(containerHeader, i));
    const body = Buffer.concat([cipher.update(slice), cipher.final()]);
    const tag = cipher.getAuthTag();
    const lenPrefix = Buffer.alloc(4);
    lenPrefix.writeUInt32BE(body.length + tag.length, 0);
    parts.push(lenPrefix, ivs[i], body, tag);
  }
  return { container: Buffer.concat(parts), header, key };
}

// Feste Eingaben. Die Salt-/IV-Werte sind erkennbar kuenstlich, damit niemand
// sie fuer echtes Schluesselmaterial haelt.
const SALT = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex');
const iv = (n) => Buffer.alloc(IV_BYTES, n);

const cases = [
  { name: 'leerer Payload — ein Chunk mit Laenge 0', passphrase: 'pcpx-test-vector-1', plaintext: Buffer.alloc(0), ivs: [iv(0x11)] },
  { name: 'ein Byte', passphrase: 'pcpx-test-vector-1', plaintext: Buffer.from([0x41]), ivs: [iv(0x22)] },
  { name: 'UTF-8-Text mit Umlauten und Emoji', passphrase: 'pcpx-test-vector-1', plaintext: Buffer.from('Grüße aus Schweden 🔐', 'utf8'), ivs: [iv(0x33)] },
  { name: 'Passphrase mit Sonderzeichen', passphrase: 'pß·🔑·4096', plaintext: pattern(1024), ivs: [iv(0x44)] },
  { name: 'Untergrenze der Iterationen', passphrase: 'pcpx-test-vector-1', iterations: 180_000, plaintext: pattern(64), ivs: [iv(0x55)] },
  { name: 'genau ein voller Chunk', passphrase: 'pcpx-test-vector-1', plaintext: pattern(CHUNK_SIZE), ivs: [iv(0x66)], inline: false },
  { name: 'zwei Chunks — zweiter angebrochen', passphrase: 'pcpx-test-vector-1', plaintext: pattern(CHUNK_SIZE + 17), ivs: [iv(0x77), iv(0x88)], inline: false },
];

const vectors = cases.map((c) => {
  const iterations = c.iterations ?? ITERATIONS;
  const { container, key } = buildContainer({ ...c, salt: SALT, iterations });
  const inline = c.inline !== false;
  const v = {
    name: c.name,
    passphrase: c.passphrase,
    saltB64u: b64u(SALT),
    iterations,
    derivedKeyB64u: b64u(key),
    payloadSize: c.plaintext.length,
    totalChunks: Math.max(1, Math.ceil(c.plaintext.length / CHUNK_SIZE)),
    ivsB64u: c.ivs.map(b64u),
    containerSize: container.length,
    containerSha256B64u: b64u(createHash('sha256').update(container).digest()),
  };
  if (inline) {
    v.plaintextB64u = b64u(c.plaintext);
    v.containerB64u = b64u(container);
  } else {
    // Zu gross zum Einbetten. Der Klartext ist reproduzierbar, also reicht die Regel.
    v.plaintextRule = 'byte[i] = (i * 31 + 7) mod 256';
    v.plaintextSha256B64u = b64u(createHash('sha256').update(c.plaintext).digest());
  }
  return v;
});

mkdirSync(dirname(OUT), { recursive: true });
writeFileSync(OUT, JSON.stringify({
  format: 'PCPX1-ENC-v2',
  specification: 'docs/PCPX1-ENC-v2.md',
  note: 'Erzeugt von tools/spec/build-vectors.mjs ohne Beteiligung des SDK. Nicht von Hand bearbeiten.',
  chunkSize: CHUNK_SIZE,
  vectors,
}, null, 2) + '\n');

console.log(`${vectors.length} Vektoren -> ${OUT}`);
for (const v of vectors) console.log(`  ${String(v.containerSize).padStart(8)} B  ${v.name}`);
