// Erzeugt Kompatibilitaets-Fixtures mit dem ALTEN Frontend-Code.
//
// WICHTIG: Dieses Skript importiert bewusst aus ../../../src/. Es wurde EINMAL
// ausgefuehrt, bevor die Krypto ins SDK gewandert ist; das Ergebnis liegt als
// tests/fixtures/legacy-containers.json im Repo und ist eingefroren.
//
// Nach der SDK-Umstellung re-exportieren die src/-Module das SDK. Ein erneuter
// Lauf wuerde also das SDK gegen sich selbst testen und waere wertlos. Das
// Skript bleibt nur zur Nachvollziehbarkeit im Repo — NICHT erneut ausfuehren
// und das Ergebnis ueberschreiben.

import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import {
  ITERATIONS,
  bytesToBase64,
  base64ToBytes,
  deriveKey,
  encryptFile,
} from '../../../src/crypto.ts';
import { createEncryptedPayload } from '../../../src/payload.ts';
import { buildSplitPassphrase } from '../../../src/crypto/pcpx-v2.ts';

const here = dirname(fileURLToPath(import.meta.url));

// Feste Testwerte statt Zufall — die Fixtures sollen reproduzierbar
// beschreibbar sein. Es sind reine Testdaten, keine echten Secrets.
const SALT = base64ToBytes('c2FsdC1mb3ItcGNweC1zZGstdGVzdHM');
const LINK_SECRET = base64ToBytes('bGlua1NlY3JldC0xNmJ5dGU');
const ACCESS_SECRET = base64ToBytes('YWNjZXNzU2VjcmV0LTE2Ynk');

async function blobToBase64(blob: Blob): Promise<string> {
  return bytesToBase64(new Uint8Array(await blob.arrayBuffer()));
}

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

async function build(
  name: string,
  description: string,
  passphrase: string,
  kind: 'text' | 'file',
  fileName: string,
  declaredType: string,
  content: Uint8Array
): Promise<Fixture> {
  const source = new Blob([content as BufferSource]);
  const payload = createEncryptedPayload(source, {
    version: 1,
    kind,
    name: fileName,
    type: declaredType,
    size: content.byteLength,
  });

  const key = await deriveKey(passphrase, SALT, ITERATIONS);
  const container = await encryptFile(payload, key);

  return {
    name,
    description,
    passphrase,
    saltB64: bytesToBase64(SALT),
    iterations: ITERATIONS,
    expectedKind: kind,
    expectedName: fileName,
    expectedDeclaredType: declaredType,
    expectedContentB64: bytesToBase64(content),
    containerB64: await blobToBase64(container),
  };
}

const enc = new TextEncoder();

const fixtures: Fixture[] = [
  await build(
    'text-standard',
    'Textnachricht, Standardmodus (Passphrase = linkKey aus dem Fragment)',
    'dGVzdC1saW5rLWtleS1zdGFuZGFyZA',
    'text',
    'nachricht.txt',
    'text/plain',
    enc.encode('Hallo aus dem Altbestand. Umlaute: äöüß — Emoji: \u{1F512}')
  ),
  await build(
    'file-standard',
    'Bindaerdatei, Standardmodus',
    'dGVzdC1saW5rLWtleS1maWxl',
    'file',
    'bericht.pdf',
    'application/pdf',
    new Uint8Array([0x25, 0x50, 0x44, 0x46, 0x2d, 0x31, 0x2e, 0x37, 0x00, 0xff, 0x10, 0x42])
  ),
  await build(
    'text-password',
    'Passwortgeschuetzt — Fragment traegt "pwd", die Passphrase kennt nur der Nutzer',
    'korrektes-pferd-batterie-klammer',
    'text',
    'geheim.txt',
    'text/plain',
    enc.encode('Passwortgeschuetzter Inhalt')
  ),
  await build(
    'text-trust-split',
    'Trust-Key-Modus: Passphrase aus linkSecret + accessSecret zusammengesetzt',
    buildSplitPassphrase(LINK_SECRET, ACCESS_SECRET),
    'text',
    'freigabe.txt',
    'text/plain',
    enc.encode('Nur nach Geraetefreigabe lesbar')
  ),
  await build(
    'file-active-mime-degraded',
    'Deklariert text/html — muss beim Auspacken auf application/octet-stream degradiert werden',
    'dGVzdC1saW5rLWtleS1taW1l',
    'file',
    'seite.html',
    'text/html',
    enc.encode('<script>alert(1)</script>')
  ),
];

const out = {
  note:
    'Eingefroren mit dem Frontend-Code VOR der SDK-Extraktion. Enthaelt ausschliesslich ' +
    'Testdaten und die zugehoerigen Test-Passphrasen — keine echten Secrets.',
  generatedFrom: 'src/crypto.ts, src/payload.ts, src/crypto/pcpx-v2.ts',
  format: 'PCPX1-ENC-v2',
  fixtures,
};

const target = join(here, 'fixtures', 'legacy-containers.json');
writeFileSync(target, JSON.stringify(out, null, 2) + '\n');
console.log(`${fixtures.length} Fixtures geschrieben: ${target}`);
