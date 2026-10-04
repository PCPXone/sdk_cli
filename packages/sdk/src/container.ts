// PCPX1-ENC-v2 — clientseitige Container-Krypto.
//
// Unveraendert aus src/crypto.ts uebernommen (SDK-Extraktion, Masterplan
// Schritt 2). Algorithmen, Parameter und Byte-Format sind identisch;
// Byte-Kompatibilitaet zu bestehenden Links ist Pflicht.
//
// Keine DOM-Abhaengigkeiten — laeuft im Browser, im Web Worker und in Node 20+.
//
// Haertung ggue. Original (Audit 2026-07-22):
//  - PBKDF2-Iterationen 180k -> 600k (OWASP-Empfehlung fuer PBKDF2-HMAC-SHA256).
//  - Iterationszahl wird beim Entschluesseln AUS DEM HEADER gelesen (der Header ist
//    per AAD an jeden Chunk gebunden, also authentifiziert) und gegen eine harte
//    Untergrenze geprueft. Dadurch ist die Erhoehung abwaertskompatibel, ohne dass
//    ein Angreifer die Iterationszahl herunterhandeln koennte.
//  - Legacy-V1-Pfad entfernt: V1 band weder AAD noch Chunk-Index, ein boesartiger
//    Server konnte V1-Chunks unbemerkt umordnen oder abschneiden.

export const CHUNK_SIZE = 5 * 1024 * 1024; // 5 MB

/** Iterationen für NEU erzeugte Container. */
export const ITERATIONS = 600_000;
/** Untergrenze für bestehende Container. Alles darunter wird abgelehnt. */
export const MIN_ACCEPTED_ITERATIONS = 180_000;
/** Obergrenze als DoS-Schutz gegen manipulierte Header. */
export const MAX_ACCEPTED_ITERATIONS = 4_000_000;

const V2_MAGIC = 'PCPX1-ENC-v2\n';
const MAX_HEADER_BYTES = 16 * 1024;
const GCM_TAG_BYTES = 16;
const IV_BYTES = 12;
// Includes encrypted payload metadata; aligned with the server's 64 MiB limit.
const MAX_CONTAINER_BYTES = 64 * 1024 * 1024;
const derivedIterations = new WeakMap<CryptoKey, number>();

export type EncryptionHeaderV2 = {
  version: 2;
  alg: 'AES-GCM';
  kdf: 'PBKDF2-SHA256';
  iterations: number;
  chunkSize: number;
  payloadSize: number;
  totalChunks: number;
  aad: 'PCPX1-CHUNK-AAD-v1';
};

/** Gibt dem Browser zwischen schweren Chunk-Operationen kurz Zeit. */
const yieldToMain = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

export async function deriveKey(
  passphrase: string,
  salt: Uint8Array,
  iterations: number = ITERATIONS
): Promise<CryptoKey> {
  if (typeof passphrase !== 'string' || passphrase.length === 0 || passphrase.length > 4096 || salt.byteLength < 8 || salt.byteLength > 96) {
    throw new Error('Unzulässiges Schlüsselmaterial.');
  }
  if (!Number.isSafeInteger(iterations) || iterations < MIN_ACCEPTED_ITERATIONS || iterations > MAX_ACCEPTED_ITERATIONS) {
    throw new Error('Unzulässige KDF-Parameter.');
  }
  const passwordBytes = new TextEncoder().encode(passphrase);
  let material: CryptoKey;
  try { material = await crypto.subtle.importKey(
    'raw',
    passwordBytes,
    'PBKDF2',
    false,
    ['deriveKey']
  ); } finally { passwordBytes.fill(0); }
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: salt as BufferSource, iterations, hash: 'SHA-256' },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
  derivedIterations.set(key, iterations);
  return key;
}

function buildChunkAad(containerHeader: Uint8Array, chunkIndex: number): Uint8Array {
  const aad = new Uint8Array(containerHeader.byteLength + 4);
  aad.set(containerHeader, 0);
  new DataView(aad.buffer).setUint32(containerHeader.byteLength, chunkIndex, false);
  return aad;
}

export async function encryptFile(file: Blob, key: CryptoKey, onProgress?: (p: number) => void): Promise<Blob> {
  if (key.type !== 'secret' || key.algorithm.name !== 'AES-GCM' || (key.algorithm as AesKeyAlgorithm).length !== 256 || !key.usages.includes('encrypt')) throw new Error('AES-256-GCM-Schlüssel erforderlich.');
  const knownIterations = derivedIterations.get(key);
  if (knownIterations !== undefined && knownIterations !== ITERATIONS) throw new Error('Neue Container erfordern die aktuellen PBKDF2-Parameter.');
  if (file.size > MAX_CONTAINER_BYTES - MAX_HEADER_BYTES - 1024) throw new Error('Payload zu groß.');
  const totalChunks = Math.max(1, Math.ceil(file.size / CHUNK_SIZE));
  const header: EncryptionHeaderV2 = {
    version: 2,
    alg: 'AES-GCM',
    kdf: 'PBKDF2-SHA256',
    iterations: ITERATIONS,
    chunkSize: CHUNK_SIZE,
    payloadSize: file.size,
    totalChunks,
    aad: 'PCPX1-CHUNK-AAD-v1',
  };

  const headerBytes = new TextEncoder().encode(JSON.stringify(header));
  const magicBytes = new TextEncoder().encode(V2_MAGIC);

  const containerHeader = new Uint8Array(magicBytes.byteLength + 4 + headerBytes.byteLength);
  containerHeader.set(magicBytes, 0);
  new DataView(containerHeader.buffer).setUint32(magicBytes.byteLength, headerBytes.byteLength, false);
  containerHeader.set(headerBytes, magicBytes.byteLength + 4);

  const chunks: Blob[] = [new Blob([containerHeader])];

  for (let i = 0; i < totalChunks; i++) {
    const start = i * CHUNK_SIZE;
    const chunkData = await file.slice(start, Math.min(start + CHUNK_SIZE, file.size)).arrayBuffer();

    const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
    let encrypted: ArrayBuffer;
    try { encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: buildChunkAad(containerHeader, i) },
      key,
      chunkData
    ); } finally { new Uint8Array(chunkData).fill(0); }

    const chunkHeader = new Uint8Array(4);
    new DataView(chunkHeader.buffer).setUint32(0, encrypted.byteLength, false);

    chunks.push(new Blob([chunkHeader, iv, encrypted]));
    onProgress?.(Math.round(((i + 1) / totalChunks) * 100));
    await yieldToMain();
  }

  return new Blob(chunks, { type: 'application/octet-stream' });
}

type ContainerInfo = {
  header: EncryptionHeaderV2;
  containerHeader: Uint8Array;
};

/**
 * Liest und validiert den unverschlüsselten Container-Header.
 *
 * Der Header ist zwar im Klartext, aber vollständig per AAD an jeden AES-GCM-Chunk
 * gebunden — jede Manipulation lässt die Entschlüsselung fehlschlagen. Trotzdem
 * werden alle Felder vorab hart geprüft, damit manipulierte Container nicht erst
 * in der Krypto oder in einer Allokation scheitern.
 */
async function readContainerInfo(blob: Blob): Promise<ContainerInfo> {
  if (blob.size > MAX_CONTAINER_BYTES) throw new Error('Container zu groß.');
  const magicBytes = new TextEncoder().encode(V2_MAGIC);
  if (blob.size < magicBytes.byteLength + 4) {
    throw new Error('Kein gültiger PCPX-Container.');
  }

  const magic = new TextDecoder().decode(await blob.slice(0, magicBytes.byteLength).arrayBuffer());
  if (magic !== V2_MAGIC) {
    throw new Error('Kein gültiger PCPX-Container.');
  }

  const lenBuf = await blob.slice(magicBytes.byteLength, magicBytes.byteLength + 4).arrayBuffer();
  const headerLength = new DataView(lenBuf).getUint32(0, false);
  if (headerLength <= 0 || headerLength > MAX_HEADER_BYTES) {
    throw new Error('Ungültige Header-Größe.');
  }

  const headerJsonBuf = await blob
    .slice(magicBytes.byteLength + 4, magicBytes.byteLength + 4 + headerLength)
    .arrayBuffer();
  if (headerJsonBuf.byteLength !== headerLength) throw new Error('Header unvollständig.');

  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(headerJsonBuf));
  } catch {
    throw new Error('Header ist kein gültiges JSON.');
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error('Ungültige Header-Felder.');
  }

  const header = parsed as EncryptionHeaderV2;
  const expectedTotalChunks =
    header.chunkSize === CHUNK_SIZE ? Math.max(1, Math.ceil(header.payloadSize / header.chunkSize)) : Number.NaN;

  if (
    header.version !== 2 ||
    header.alg !== 'AES-GCM' ||
    header.kdf !== 'PBKDF2-SHA256' ||
    header.aad !== 'PCPX1-CHUNK-AAD-v1' ||
    header.chunkSize !== CHUNK_SIZE ||
    !Number.isSafeInteger(header.iterations) ||
    header.iterations < MIN_ACCEPTED_ITERATIONS ||
    header.iterations > MAX_ACCEPTED_ITERATIONS ||
    !Number.isSafeInteger(header.payloadSize) ||
    header.payloadSize < 0 ||
    !Number.isSafeInteger(header.totalChunks) ||
    header.totalChunks !== expectedTotalChunks
  ) {
    throw new Error('Ungültige Header-Felder.');
  }

  const containerHeader = new Uint8Array(
    await blob.slice(0, magicBytes.byteLength + 4 + headerLength).arrayBuffer()
  );
  // Reject inconsistent/truncated containers BEFORE expensive PBKDF2 or allocations.
  const expectedSize = containerHeader.byteLength + header.payloadSize + header.totalChunks * (4 + IV_BYTES + GCM_TAG_BYTES);
  if (!Number.isSafeInteger(expectedSize) || expectedSize !== blob.size) throw new Error('Ungültige Container-Länge.');
  return { header, containerHeader };
}

/** Returns bounded KDF parameters; authenticity is established only by successful GCM decryption. */
export async function readContainerIterations(blob: Blob): Promise<number> {
  const { header } = await readContainerInfo(blob);
  return header.iterations;
}

export async function decryptFile(
  blob: Blob,
  key: CryptoKey,
  originalName: string,
  type: string,
  onProgress?: (p: number) => void
): Promise<File> {
  const { header, containerHeader } = await readContainerInfo(blob);

  const chunks: Blob[] = [];
  let offset = containerHeader.byteLength;
  let decryptedSize = 0;

  for (let i = 0; i < header.totalChunks; i++) {
    if (offset + 4 + IV_BYTES + GCM_TAG_BYTES > blob.size) {
      throw new Error('Verschlüsselte Datei endet unerwartet.');
    }

    const ciphertextLength = new DataView(await blob.slice(offset, offset + 4).arrayBuffer()).getUint32(0, false);
    offset += 4;

    const expectedPlainSize =
      i === header.totalChunks - 1 ? header.payloadSize - i * header.chunkSize : header.chunkSize;
    if (ciphertextLength !== expectedPlainSize + GCM_TAG_BYTES) {
      throw new Error('Ungültige Chunk-Länge.');
    }

    const iv = new Uint8Array(await blob.slice(offset, offset + IV_BYTES).arrayBuffer());
    offset += IV_BYTES;

    const ciphertext = await blob.slice(offset, offset + ciphertextLength).arrayBuffer();
    if (ciphertext.byteLength !== ciphertextLength) throw new Error('Chunk-Inhalt unvollständig.');

    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv, additionalData: buildChunkAad(containerHeader, i) },
      key,
      ciphertext
    );

    chunks.push(new Blob([decrypted]));
    new Uint8Array(decrypted).fill(0);
    decryptedSize += decrypted.byteLength;
    offset += ciphertextLength;

    onProgress?.(Math.round(((i + 1) / header.totalChunks) * 100));
    await yieldToMain();
  }

  if (offset !== blob.size) throw new Error('Unerwartete Daten am Ende der Datei.');
  if (decryptedSize !== header.payloadSize) throw new Error('Entschlüsselte Größe passt nicht zum Header.');

  return new File(chunks, originalName, { type });
}
