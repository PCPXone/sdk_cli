// @pcpx/sdk — oeffentliche Oberflaeche.
//
// Enthaelt die komplette Krypto- und Link-Format-Logik von pcpx.one, ohne
// DOM-Bezug: nutzbar im Browser, im Web Worker und in Node 20+.
//
// Bewusst NICHT hier: Web-Worker-Verdrahtung, IndexedDB-Schluesselhaltung und
// HTTP-Aufrufe. Das bleibt Sache der jeweiligen Anwendung.

export {
  bytesToBase64,
  base64ToBytes,
  randomBytes,
  randomToken,
} from './base64.ts';

export {
  CHUNK_SIZE,
  ITERATIONS,
  MIN_ACCEPTED_ITERATIONS,
  MAX_ACCEPTED_ITERATIONS,
  deriveKey,
  encryptFile,
  decryptFile,
  readContainerIterations,
  type EncryptionHeaderV2,
} from './container.ts';

export {
  NEUTRAL_MIME_TYPE,
  safeMimeType,
  createEncryptedPayload,
  unpackDecryptedPayload,
  type PayloadMetadata,
} from './payload.ts';

export {
  TRUST_LINK_SECRET_BYTES,
  TRUST_ACCESS_SECRET_BYTES,
  buildSplitPassphrase,
  importRecipientPublicKey,
  sealAccessSecretForRecipient,
  openAccessPackage,
  publicKeyFingerprint,
  sealAccessSecretForDevice,
  openDeviceAccessPackage,
  FINGERPRINT_PATTERN,
  type SealedAccessV3,
  type AccessRequest,
  type ApprovedAccessPackage,
} from './trust.ts';

export {
  PASSWORD_PLACEHOLDER,
  parseSecretFragment,
  buildSecretLink,
  sha256Base64Url,
  buildLinkProof,
  type FragmentParams,
} from './link.ts';
export { readEncryptedResponse } from './transport.ts';
