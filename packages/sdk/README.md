# @pcpx/sdk

Die Krypto- und Link-Format-Logik von pcpx.one als eigenständiges Package.
Läuft im Browser, im Web Worker und in Node 20+. Keine Runtime-Dependencies —
alles über native WebCrypto.

## Warum es das gibt

Vorher lag die Krypto direkt im Frontend. Damit hätte jeder weitere Client
(API-Beispiele, CLI, PowerShell) sie nachbauen müssen, und jeder Nachbau ist
eine Gelegenheit, das Format subtil zu brechen. Jetzt gibt es genau eine
Implementierung — und seit Oktober 2026 auch eine byte-genaue Beschreibung des
Formats, damit Nachbauten nicht raten müssen.

## Installation

```sh
npm install @pcpx/sdk
```

## Das Format

`SPEC.md` in diesem Paket beschreibt `PCPX1-ENC-v2` byte-genau: Container,
Schlüsselableitung, AAD-Bindung, Payload-Schicht, Linkformat und die
Prüfungen, die ein konformer Leser durchführen muss.

`vectors/pcpx1-enc-v2.json` enthält sieben Testvektoren mit Passphrase, Salt,
abgeleitetem Schlüssel, IVs sowie Größe und SHA-256 des Containers. Wer eine
eigene Implementierung schreibt, prüft zuerst PBKDF2 gegen `derivedKeyB64u` —
scheitert das, ist alles Weitere sinnlos.

Die Vektoren entstehen ohne Beteiligung dieses SDK, nur mit `node:crypto`.
Sonst prüfte sich die Implementierung gegen sich selbst.

## Was drin ist

| Modul | Inhalt |
|---|---|
| `base64.ts` | Base64url ohne Padding, Zufallsbytes |
| `container.ts` | PCPX1-ENC-v2: AES-256-GCM in 5-MB-Chunks, PBKDF2-SHA256, AAD-Bindung |
| `payload.ts` | Metadaten-Container, MIME-Allowlist, Dateinamen-Bereinigung |
| `trust.ts` | Trust-Modus: Key-Splitting, Freigabe-Paket (ECDH P-256 → HKDF → AES-GCM), Fingerprint |
| `link.ts` | Fragment-Format, Link-Bau, Besitznachweis |

## Was bewusst NICHT drin ist

Alles Umgebungsabhängige bleibt bei der Anwendung: die Web-Worker-Verdrahtung,
die gerätelokale Schlüsselhaltung in IndexedDB und sämtliche HTTP-Aufrufe.
Das SDK hat keine DOM-Abhängigkeiten.

## Format-Stabilität

Das Byte-Format ist eingefroren. Bestehende Links müssen aufgehen, deshalb
liegen unter `tests/fixtures/legacy-containers.json` Container, die mit dem
Frontend-Code **vor** der Extraktion erzeugt wurden. Die Tests entschlüsseln
sie bei jedem Lauf.

```
npm run test:sdk
```

Das Generatorskript `tests/generate-legacy-fixtures.mts` ist nur zur
Nachvollziehbarkeit da und darf **nicht** erneut ausgeführt werden — es würde
das SDK gegen sich selbst testen und den Beweis wertlos machen.

## Nutzung

```ts
import {
  ITERATIONS, deriveKey, encryptFile, decryptFile,
  createEncryptedPayload, unpackDecryptedPayload,
  randomBytes, bytesToBase64, buildSecretLink,
} from '@pcpx/sdk';

const content = new TextEncoder().encode('geheim');
const payload = createEncryptedPayload(new Blob([content]), {
  version: 1, kind: 'text', name: 'notiz.txt',
  type: 'text/plain', size: content.byteLength,
});

const salt = randomBytes(16);
const passphrase = bytesToBase64(randomBytes(16));
const key = await deriveKey(passphrase, salt, ITERATIONS);
const container = await encryptFile(payload, key);
// container -> Server, passphrase -> nur in den Link-Fragment-Teil
```

Der Schlüssel gehört ausschließlich hinter das `#` im Link. Er darf nie in einen
Request, in ein Log oder in eine Fehlermeldung geraten.
