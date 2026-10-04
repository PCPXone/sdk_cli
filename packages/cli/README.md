# pcpx — CLI

Einmal-Secrets aus Scripts und Pipelines verschicken. Sämtliche Krypto läuft
über `@pcpx/sdk` — verschlüsselt wird **lokal**, die API sieht nur Ciphertext,
der Schlüssel steht ausschließlich im Fragment-Teil des ausgegebenen Links.

## Installation

```sh
npm install -g @pcpx/cli
```

Oder ohne Installation:

```sh
npx @pcpx/cli create --text "..."
```

Node 20 oder neuer. Keine Runtime-Dependencies — die Krypto aus `@pcpx/sdk` ist
in die Binärdatei gebündelt.

## Nutzung (im Repo)

```bash
# Alias fuer die laufende Shell
alias pcpx='npm run --silent pcpx --'

export PCPX_API_KEY="pcpx_live_..."       # noetig fuer create/delete
export PCPX_API_URL="https://pcpx.one"    # Default
export PCPX_GATE="..."                    # nur Staging: X-Pcpx-Gate-Header
                                          # (nginx-Riegel auf test.pcpx.one)

pcpx create --text "Zugangsdaten: ..." --ttl 3600
pcpx create --file bericht.pdf --json
pcpx open "https://pcpx.one/#<id>:<key>" --out bericht.pdf
pcpx delete <id> --token <deleteToken>
```

`open` braucht **keinen** API-Key und öffnet auch Links, die im Browser
erstellt wurden — derselbe Speicher, dieselbe Burn-Semantik: der erste Abruf
verbraucht das Secret, egal ob Browser oder CLI.

Statt Umgebungsvariablen geht auch `~/.config/pcpx/config.json`:

```json
{ "apiUrl": "https://pcpx.one", "apiKey": "pcpx_live_...", "gate": "..." }
```

Umgebungsvariablen haben Vorrang. Den Key nie als Argument übergeben — er
landet sonst in der Shell-History.

## Exit-Codes

| Code | Bedeutung |
|---|---|
| 0 | Erfolg |
| 1 | Laufzeitfehler (API nicht erreichbar, Entschlüsselung fehlgeschlagen …) |
| 2 | Bedienfehler (fehlende Argumente, kein API-Key …) |
| 3 | Nicht abrufbar: schon gelesen/abgelaufen, Trust-Modus oder passwortgeschützt |

`--json` liefert auf stdout bzw. stderr maschinenlesbare Objekte
(`{"ok":true,...}` / `{"ok":false,"error":"..."}`).

## Bewusste Grenzen (v1)

- Trust-Modus-Links und passwortgeschützte Links öffnet die CLI nicht —
  sie erkennt beide **vor** dem Abruf und bricht ab, ohne das Secret zu
  verbrennen. Der Browser-Flow bleibt dafür zuständig.
- `--max-views` akzeptiert nur `1` (Einmal-Abruf, wie die API).
- Schlüssel, Fragmente und Klartexte erscheinen in keiner Fehlermeldung.
