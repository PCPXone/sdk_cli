// Payload-Container (SDK — unveraendert aus src/payload.ts uebernommen): bindet Dateiname/-typ als Metadaten an den Klartext, damit
// beides mitverschlüsselt wird und der Server es nie sieht.
//
// Härtung ggü. Original (Audit 2026-07-22):
//  - `safeMimeType` akzeptierte jeden String <= 120 Zeichen, also auch `text/html`
//    oder `image/svg+xml`. Dieser Typ wanderte in `URL.createObjectURL()`, womit ein
//    bösartiger Absender dem Empfänger ein aktives Dokument in dessen eigenem
//    Origin unterschieben konnte. Jetzt: Allowlist inerter Typen, alles andere
//    fällt auf `application/octet-stream` zurück.
//  - `JSON.parse` der Metadaten war als einzige Stelle nicht abgesichert und warf,
//    statt wie alle Nachbarpfade auf 'legacy' zurückzufallen.
//  - `metadata.size` wird BEWUSST NICHT gegen die tatsächliche Größe geprüft; die
//    Begründung steht an der Prüfstelle in `unpackDecryptedPayload`.

const PAYLOAD_METADATA_MAGIC = 'PCPX1-PAYLOAD-METADATA-v1\n';
const MAX_METADATA_BYTES = 16 * 1024;

export const NEUTRAL_MIME_TYPE = 'application/octet-stream';

export type PayloadMetadata = {
  version: 1;
  kind: 'text' | 'file';
  name: string;
  type: string;
  size: number;
};

const payloadEncoder = new TextEncoder();
const payloadDecoder = new TextDecoder();
const payloadMagicBytes = payloadEncoder.encode(PAYLOAD_METADATA_MAGIC);

/**
 * MIME-Typen, die der Browser garantiert NICHT als aktives Dokument im eigenen
 * Origin ausführt. Bewusst ohne text/html, application/xhtml+xml, *+xml und
 * image/svg+xml — die sind alle skriptfähig.
 */
const INERT_MIME_TYPES = new Set([
  'text/plain',
  'application/json',
  'application/pdf',
  'application/zip',
  'application/gzip',
  'application/octet-stream',
  'image/png',
  'image/jpeg',
  'image/gif',
  'image/webp',
  'image/avif',
  'audio/mpeg',
  'audio/ogg',
  'audio/wav',
  'video/mp4',
  'video/webm',
]);

/**
 * Normalisiert einen deklarierten MIME-Typ auf einen inerten Wert.
 * Unbekannte oder aktive Typen werden zu application/octet-stream degradiert.
 */
export function safeMimeType(type: unknown): string {
  if (typeof type !== 'string') return NEUTRAL_MIME_TYPE;
  const normalized = type.split(';')[0].trim().toLowerCase();
  if (!normalized || normalized.length > 120) return NEUTRAL_MIME_TYPE;
  return INERT_MIME_TYPES.has(normalized) ? normalized : NEUTRAL_MIME_TYPE;
}

export function createEncryptedPayload(source: Blob, metadata: PayloadMetadata): Blob {
  const metadataBytes = payloadEncoder.encode(JSON.stringify(metadata));
  if (metadataBytes.byteLength > MAX_METADATA_BYTES) {
    throw new Error('Dateimetadaten sind zu groß.');
  }

  const lengthPrefix = new Uint8Array(4);
  new DataView(lengthPrefix.buffer).setUint32(0, metadataBytes.byteLength, false);

  return new Blob([payloadMagicBytes, lengthPrefix, metadataBytes, source], { type: NEUTRAL_MIME_TYPE });
}

function sanitizeDecryptedFileName(name: unknown): string {
  if (typeof name !== 'string') return 'decrypted_secret';
  // Pfadtrenner, Windows-Sonderzeichen und Steuerzeichen entfernen; zusätzlich
  // führende Punkte, damit keine versteckten Dateien entstehen.
  const cleaned = name
    .replace(/[\\/:*?"<>|\u0000-\u001f\u007f]/g, '_')
    .replace(/[\u202a-\u202e\u2066-\u2069]/g, '_')
    .replace(/^\.+/, '')
    .trim()
    .replace(/^\.+/, '')
    .slice(0, 180).replace(/[. ]+$/, '');
  if (!cleaned || cleaned === '.' || cleaned === '..') return 'decrypted_secret';
  if (/^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(cleaned)) return `_${cleaned}`;
  return cleaned;
}

function asLegacy(blob: Blob): { file: File; kind: 'legacy' } {
  return {
    file: new File([blob], 'decrypted_secret', { type: NEUTRAL_MIME_TYPE }),
    kind: 'legacy',
  };
}

export async function unpackDecryptedPayload(
  decryptedBlob: Blob
): Promise<{ file: File; kind: PayloadMetadata['kind'] | 'legacy'; declaredType: string }> {
  const headerLength = payloadMagicBytes.byteLength + 4;
  if (decryptedBlob.size < headerLength) {
    return { ...asLegacy(decryptedBlob), declaredType: NEUTRAL_MIME_TYPE };
  }

  const header = new Uint8Array(await decryptedBlob.slice(0, headerLength).arrayBuffer());
  const hasMagic = payloadMagicBytes.every((byte, index) => header[index] === byte);
  if (!hasMagic) {
    return { ...asLegacy(decryptedBlob), declaredType: NEUTRAL_MIME_TYPE };
  }

  const metadataLength = new DataView(header.buffer, payloadMagicBytes.byteLength, 4).getUint32(0, false);
  const dataOffset = headerLength + metadataLength;
  if (metadataLength <= 0 || metadataLength > MAX_METADATA_BYTES || dataOffset > decryptedBlob.size) {
    return { ...asLegacy(decryptedBlob), declaredType: NEUTRAL_MIME_TYPE };
  }

  let metadata: Partial<PayloadMetadata>;
  try {
    metadata = JSON.parse(payloadDecoder.decode(await decryptedBlob.slice(headerLength, dataOffset).arrayBuffer()));
  } catch {
    return { ...asLegacy(decryptedBlob), declaredType: NEUTRAL_MIME_TYPE };
  }

  if (!metadata || typeof metadata !== 'object' || Array.isArray(metadata) || metadata.version !== 1 || (metadata.kind !== 'text' && metadata.kind !== 'file')) {
    return { ...asLegacy(decryptedBlob), declaredType: NEUTRAL_MIME_TYPE };
  }

  // `metadata.size` wird bewusst NICHT gegen die tatsächliche Größe geprüft.
  // Der gesamte Payload liegt innerhalb des AES-GCM-authentifizierten Bereichs —
  // stimmt das Tag, sind die Metadaten unverändert. Eine Gleichheitsprüfung
  // brächte also keinen Sicherheitsgewinn, würde aber bei jedem Produzenten, der
  // die Größe anders zählt (UTF-16-Länge statt UTF-8-Bytes), den Inhalt still
  // auf 'legacy' degradieren. Das Feld bleibt rein informativ.
  const content = decryptedBlob.slice(dataOffset, decryptedBlob.size);
  const declaredType = safeMimeType(metadata.type);
  const name = sanitizeDecryptedFileName(metadata.name);

  // Der File wird bewusst IMMER mit neutralem Typ gebaut. Der deklarierte Typ
  // dient nur der Anzeige; er darf nie bestimmen, wie der Browser ein daraus
  // erzeugtes blob:-Dokument interpretiert.
  return {
    file: new File([content], name, { type: NEUTRAL_MIME_TYPE }),
    kind: metadata.kind,
    declaredType,
  };
}
