#!/usr/bin/env -S node --import tsx
// pcpx — Kommandozeilen-Client fuer pcpx.one (Masterplan Schritt 7, Teil A).
//
// Saemtliche Krypto laeuft ueber @pcpx/sdk — hier gibt es keine eigene.
// Zero-Knowledge-Regeln der CLI:
//  - Der Link-Schluessel (Fragment) wird lokal erzeugt und verlaesst die
//    Maschine ausschliesslich als Teil des ausgegebenen Links.
//  - Schluessel, Fragmente und Klartexte tauchen in keiner Fehlermeldung auf.
//  - Der API-Key kommt aus PCPX_API_KEY oder der Config-Datei — nie aus
//    Argumenten (Shell-History).
//
// Exit-Codes: 0 Erfolg · 1 Laufzeitfehler · 2 Bedienfehler · 3 nicht abrufbar
// (Trust-Modus oder bereits gelesen/abgelaufen).

import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { basename, join } from 'node:path';
import { homedir } from 'node:os';
import process from 'node:process';

import {
  ITERATIONS,
  base64ToBytes,
  buildSecretLink,
  bytesToBase64,
  createEncryptedPayload,
  decryptFile,
  deriveKey,
  encryptFile,
  parseSecretFragment,
  randomBytes,
  readContainerIterations,
  readEncryptedResponse,
  unpackDecryptedPayload,
} from '../../sdk/src/index.ts';

type Config = { apiUrl: string; apiKey: string | null; gate: string | null; linkUrl: string };

const USAGE = `pcpx — Einmal-Secrets von der Kommandozeile (Zero-Knowledge)

NUTZUNG
  pcpx create (--text "..." | --file <pfad>) [--ttl <sekunden>] [--max-views 1] [--json]
  pcpx open <link> [--out <pfad>] [--json]
  pcpx delete <id> --token <deleteToken> [--json]

KONFIGURATION
  PCPX_API_KEY   API-Key (pcpx_live_...) — noetig fuer create und delete.
                 Nie als Argument uebergeben (landet in der Shell-History).
  PCPX_API_URL   Basis-URL, Standard: https://pcpx.one
  Optional: ~/.config/pcpx/config.json mit { "apiUrl": "...", "apiKey": "..." }
  (Umgebungsvariablen haben Vorrang.)

BEISPIELE
  pcpx create --text "Zugangsdaten: ..." --ttl 3600
  pcpx create --file bericht.pdf
  pcpx open "https://pcpx.one/#<id>:<key>" --out bericht.pdf
  pcpx delete <id> --token <deleteToken>

  open funktioniert ohne API-Key — auch fuer Links, die im Browser erstellt
  wurden. Der erste Abruf brennt das Secret, im Browser wie hier.`;

function loadConfig(): Config {
  let fileConf: Partial<Config> = {};
  const confPath = process.env.PCPX_CONFIG ?? join(homedir(), '.config', 'pcpx', 'config.json');
  if (existsSync(confPath)) {
    try {
      fileConf = JSON.parse(readFileSync(confPath, 'utf8')) as Partial<Config>;
    } catch {
      fail(1, `Config-Datei ist kein gültiges JSON: ${confPath}`);
    }
  }
  return {
    apiUrl: (process.env.PCPX_API_URL ?? fileConf.apiUrl ?? 'https://pcpx.one').replace(/\/$/, ''),
    apiKey: process.env.PCPX_API_KEY ?? fileConf.apiKey ?? null,
    // Staging-Riegel: test.pcpx.one beantwortet /v1 nur mit passendem
    // X-Pcpx-Gate-Header (nginx, Wunsch vom 15.08.2026). Zweites Geheimnis
    // neben dem API-Key; faellt weg, sobald die API oeffentlich ist.
    gate: process.env.PCPX_GATE ?? fileConf.gate ?? null,
    // Die API kann auf einer eigenen Subdomain liegen (api.pcpx.one), der
    // ausgegebene Link muss aber auf dem Frontend oeffnen (pcpx.one) — dort
    // liegt der Viewer, der das Fragment entschluesselt. Ohne Angabe gilt
    // die API-Basis, damit lokale Tests unveraendert funktionieren.
    linkUrl: (process.env.PCPX_LINK_URL ?? fileConf.linkUrl ?? process.env.PCPX_API_URL ?? fileConf.apiUrl ?? 'https://pcpx.one').replace(/\/$/, ''),
  };
}

/** Header fuer /v1-Aufrufe: Bearer-Key plus optional der Staging-Gate-Header. */
function v1Headers(config: Config, apiKey: string, extra: Record<string, string> = {}): Record<string, string> {
  return {
    Authorization: `Bearer ${apiKey}`,
    ...(config.gate ? { 'X-Pcpx-Gate': config.gate } : {}),
    ...extra,
  };
}

// --- Argument-Handling (bewusst ohne Dependency) -----------------------------

const argv = process.argv.slice(2);
const jsonMode = argv.includes('--json');

function readFlagValue(name: string): string | undefined {
  const i = argv.indexOf(`--${name}`);
  if (i === -1) return undefined;
  const value = argv[i + 1];
  if (value === undefined || value.startsWith('--')) fail(2, `--${name} braucht einen Wert.`);
  return value;
}

function fail(code: number, message: string): never {
  if (jsonMode) console.error(JSON.stringify({ ok: false, error: message }));
  else console.error(`Fehler: ${message}`);
  process.exit(code);
}

function output(human: string, json: Record<string, unknown>): void {
  console.log(jsonMode ? JSON.stringify(json) : human);
}

function requireApiKey(config: Config): string {
  if (!config.apiKey) {
    fail(2, 'Kein API-Key. PCPX_API_KEY setzen oder in ~/.config/pcpx/config.json hinterlegen.');
  }
  return config.apiKey;
}

function secureFetch(url: string, init: RequestInit = {}): Promise<Response> {
  const parsed = new URL(url);
  if (parsed.username || parsed.password || (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(parsed.hostname)))) fail(2, 'HTTPS erforderlich; HTTP ist nur für lokale Tests erlaubt.');
  return fetch(url, { ...init, redirect: 'error', signal: init.signal ?? AbortSignal.timeout(120_000) });
}

async function parseApiError(res: Response, fallback: string): Promise<never> {
  let message = fallback;
  try {
    const data = (await res.json()) as { message?: unknown };
    if (typeof data?.message === 'string' && data.message.length <= 200) message = data.message;
  } catch {
    /* Nicht-JSON-Antwort: beim Fallback bleiben */
  }
  fail(1, `${message} (HTTP ${res.status})`);
}

// --- create ------------------------------------------------------------------

async function cmdCreate(config: Config): Promise<void> {
  const apiKey = requireApiKey(config);
  const text = readFlagValue('text');
  const file = readFlagValue('file');
  if ((text === undefined) === (file === undefined)) {
    fail(2, 'Genau eines von --text oder --file angeben.');
  }

  const maxViews = readFlagValue('max-views');
  if (maxViews !== undefined && maxViews !== '1') {
    fail(2, 'Nur --max-views 1 wird unterstützt (Einmal-Abruf).');
  }
  const ttl = readFlagValue('ttl');

  let content: Uint8Array;
  let name: string;
  let kind: 'text' | 'file';
  let mime: string;
  if (text !== undefined) {
    content = new TextEncoder().encode(text);
    name = 'nachricht.txt';
    kind = 'text';
    mime = 'text/plain';
  } else {
    if (!existsSync(file!)) fail(1, `Datei nicht gefunden: ${file}`);
    content = new Uint8Array(readFileSync(file!));
    name = basename(file!);
    kind = 'file';
    mime = 'application/octet-stream';
  }

  // Lokal verschluesseln — linkKey und Klartext verlassen die Maschine nicht.
  const payload = createEncryptedPayload(new Blob([content as BufferSource]), {
    version: 1,
    kind,
    name,
    type: mime,
    size: content.byteLength,
  });
  const salt = randomBytes(16);
  const linkKey = bytesToBase64(randomBytes(16));
  const key = await deriveKey(linkKey, salt, ITERATIONS);
  const container = await encryptFile(payload, key);

  const form = new FormData();
  form.append('ciphertext', container, 'secret.enc');
  form.append('salt', bytesToBase64(salt));
  if (ttl !== undefined) form.append('ttl', ttl);

  let res: Response;
  try {
    res = await secureFetch(`${config.apiUrl}/v1/secrets`, {
      method: 'POST',
      headers: v1Headers(config, apiKey),
      body: form,
    });
  } catch {
    fail(1, `API nicht erreichbar: ${config.apiUrl}`);
  }
  if (!res.ok) await parseApiError(res, 'Anlegen fehlgeschlagen.');

  const body = (await res.json()) as { id: string; deleteToken: string; expiresAt: number };
  const link = buildSecretLink(config.linkUrl, body.id, linkKey);

  output(
    [
      link,
      '',
      `id:          ${body.id}`,
      `läuft ab:    ${new Date(body.expiresAt).toISOString()}`,
      `deleteToken: ${body.deleteToken}`,
      '',
      'Der Link enthält den Schlüssel — nur über einen sicheren Kanal teilen.',
    ].join('\n'),
    { ok: true, link, id: body.id, deleteToken: body.deleteToken, expiresAt: body.expiresAt }
  );
}

// --- open --------------------------------------------------------------------

async function cmdOpen(config: Config): Promise<void> {
  const linkArg = argv[1];
  if (!linkArg || linkArg.startsWith('--')) fail(2, 'pcpx open <link> — der Link fehlt.');

  let parsed: URL;
  try {
    parsed = new URL(linkArg);
  } catch {
    fail(2, 'Das ist keine gültige URL.');
  }
  const fragment = parseSecretFragment(parsed.hash);
  if (!fragment) fail(2, 'Der Link enthält kein gültiges Secret-Fragment (#id:key).');
  const origin = parsed.origin;

  // Meta zuerst: verraet trustRequired, OHNE das Secret zu brennen.
  let metaRes: Response;
  try {
    metaRes = await secureFetch(`${origin}/api/secrets/${encodeURIComponent(fragment.id)}`);
  } catch {
    fail(1, `Server nicht erreichbar: ${origin}`);
  }
  if (metaRes.status === 404) fail(3, 'Nicht gefunden, bereits gelesen oder abgelaufen.');
  if (!metaRes.ok) await parseApiError(metaRes, 'Abruf fehlgeschlagen.');
  const meta = (await metaRes.json()) as { salt: string; trustRequired?: boolean };

  if (meta.trustRequired) {
    fail(3, 'Dieses Secret verlangt eine Empfänger-Freigabe (Trust-Modus). Bitte im Browser öffnen — die CLI unterstützt den Freigabe-Flow noch nicht.');
  }
  if (fragment.key === 'pwd') {
    fail(3, 'Dieses Secret ist passwortgeschützt. Bitte im Browser öffnen — die CLI unterstützt Passwort-Eingabe noch nicht.');
  }

  // Erst jetzt der Einmal-Download (brennt das Secret).
  const dlRes = await secureFetch(`${origin}/api/secrets/${encodeURIComponent(fragment.id)}/download`);
  if (dlRes.status === 404) fail(3, 'Nicht gefunden, bereits gelesen oder abgelaufen.');
  if (!dlRes.ok) await parseApiError(dlRes, 'Download fehlgeschlagen.');
  const container = await readEncryptedResponse(dlRes);

  // Iterationszahl kommt aus dem AAD-authentifizierten Container-Header.
  const iterations = await readContainerIterations(container);
  const key = await deriveKey(fragment.key, base64ToBytes(meta.salt), iterations);
  let unpacked: Awaited<ReturnType<typeof unpackDecryptedPayload>>;
  try {
    unpacked = await unpackDecryptedPayload(await decryptFile(container, key, 'payload.bin', 'application/octet-stream'));
  } catch {
    fail(1, 'Entschlüsselung fehlgeschlagen — Link unvollständig oder beschädigt. Das Secret ist jetzt verbraucht.');
  }

  const out = readFlagValue('out');
  const bytes = new Uint8Array(await unpacked.file.arrayBuffer());

  if (unpacked.kind === 'text' && out === undefined) {
    // Text landet auf stdout; --json liefert ihn als Feld.
    output(new TextDecoder().decode(bytes), {
      ok: true,
      kind: 'text',
      name: unpacked.file.name,
      content: new TextDecoder().decode(bytes),
    });
    return;
  }

  const target = out ?? unpacked.file.name;
  try { writeFileSync(target, bytes, { flag: 'wx', mode: 0o600 }); }
  catch { fail(1, 'Zieldatei existiert bereits oder kann nicht sicher angelegt werden. Bitte einen neuen --out-Pfad wählen.'); }
  output(`Gespeichert: ${target} (${bytes.byteLength} Bytes)`, {
    ok: true,
    kind: unpacked.kind,
    name: unpacked.file.name,
    path: target,
    bytes: bytes.byteLength,
  });
}

// --- delete ------------------------------------------------------------------

async function cmdDelete(config: Config): Promise<void> {
  const apiKey = requireApiKey(config);
  const id = argv[1];
  if (!id || id.startsWith('--')) fail(2, 'pcpx delete <id> --token <deleteToken> — die id fehlt.');
  const token = readFlagValue('token');
  if (!token) fail(2, '--token <deleteToken> fehlt.');

  let res: Response;
  try {
    res = await secureFetch(`${config.apiUrl}/v1/secrets/${encodeURIComponent(id)}`, {
      method: 'DELETE',
      headers: v1Headers(config, apiKey, { 'X-Pcpx-Delete-Token': token }),
    });
  } catch {
    fail(1, `API nicht erreichbar: ${config.apiUrl}`);
  }
  if (!res.ok) await parseApiError(res, 'Löschen fehlgeschlagen.');
  output('Gelöscht.', { ok: true, id });
}

// --- main --------------------------------------------------------------------

const command = argv[0];
const config = loadConfig();

switch (command) {
  case 'create':
    await cmdCreate(config);
    break;
  case 'open':
    await cmdOpen(config);
    break;
  case 'delete':
    await cmdDelete(config);
    break;
  case 'help':
  case '--help':
  case '-h':
  case undefined:
    console.log(USAGE);
    process.exit(command === undefined ? 2 : 0);
    break;
  default:
    fail(2, `Unbekanntes Kommando: ${command}. 'pcpx --help' zeigt die Nutzung.`);
}
