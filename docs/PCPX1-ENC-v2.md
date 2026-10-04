# PCPX1-ENC-v2 — Containerformat

Byte-genaue Beschreibung des Formats, das pcpx.one im Browser, in `@pcpx/sdk`,
in der CLI und im PowerShell-Modul schreibt und liest.

**Status: normativ.** Dieses Dokument beschreibt ein Format, das produktiv im
Einsatz ist. Bestehende Links müssen lesbar bleiben — jede Abweichung bricht
Container, die Nutzer bereits verschickt haben. Änderungen am Format erfordern
eine neue Versionskennung, keine Anpassung dieses Dokuments.

Referenzimplementierung: `packages/sdk/src/container.ts`.
Testvektoren: `tests/vectors/pcpx1-enc-v2.json`, erzeugt von
`tools/spec/build-vectors.mjs`, geprüft von `tests/spec-vectors.test.mts`.

## Warum es dieses Dokument gibt

Ohne byte-genaue Beschreibung muss jede neue Plattform raten oder
Implementierungscode lesen. Beides ist passiert: der Windows Secure Wrapper
schreibt `PCPX-SW-ENC-v1`, der Vault-Prototyp `SPR-VAULT-v1`. Beide nutzen
AES-256-GCM, keiner kann die Container der anderen lesen. Das war die richtige
Entscheidung — eine falsche Kompatibilitätsbehauptung wäre schlimmer als gar
keine —, aber es ist der Grund, warum es dieses Dokument braucht.

## Schichten

Von außen nach innen:

```text
Link        <origin>/#<noteId>:<linkKey>
  └─ KDF    PBKDF2-SHA256(linkKey, salt, iterations) -> AES-256-Schlüssel
       └─ Container  PCPX1-ENC-v2   (dieses Dokument, Abschnitt 4)
            └─ Payload  PCPX1-PAYLOAD-METADATA-v1   (Abschnitt 5)
                 └─ Klartext
```

Container und Payload sind unabhängig. Ein Container kann beliebige Bytes
tragen; die Payload-Schicht ist eine Konvention darüber, wie pcpx.one
Dateiname und MIME-Typ mitverschlüsselt.

## 1. Base64url

Überall Base64url **ohne Padding**: Alphabet `A–Z a–z 0–9 - _`, keine `=`.
Dekodierer müssen fehlendes Padding ergänzen.

## 2. Link und Fragment

```text
<origin>/#<noteId>:<linkKey>
```

- `noteId` — UUID v4 in Kleinbuchstaben mit Bindestrichen, vom Server vergeben.
- `linkKey` — Base64url-Zufallswert aus **16 Byte** (22 Zeichen ohne Padding),
  **oder** der Literalwert `pwd`, wenn der Inhalt passwortgeschützt ist und die
  Passphrase gar nicht im Link steht. Browser und CLI erzeugen beide 16 Byte.
  Nicht zu verwechseln mit dem Owner-Token (32 Byte), das ein eigener Wert ist
  und nicht in den Link gehört.

Das Fragment wird von Browsern nicht an Server übertragen. Darauf beruht die
Zero-Knowledge-Eigenschaft; ein konformer Client darf es niemals in einen
Request schreiben, auch nicht in Logs oder Fehlermeldungen.

Ein Leser muss Fragmente ablehnen, die länger als 4200 Zeichen sind, `/` oder
`&` enthalten, mehr als einen Doppelpunkt tragen, deren `noteId` keine UUID ist
oder deren `linkKey` Steuerzeichen enthält bzw. 4096 Zeichen überschreitet.

### Besitznachweis

```text
linkProof = base64url( SHA-256( "pcpx-link-proof|" + linkKey ) )
```

Der Präfixtext wird als UTF-8 mit dem `linkKey` **als Zeichenkette**
verkettet — nicht mit dessen dekodierten Bytes.

## 3. Schlüsselableitung

```text
key = PBKDF2-HMAC-SHA256(passphrase, salt, iterations, dkLen = 32)
```

| | |
|---|---|
| `passphrase` | UTF-8-Bytes des `linkKey` **als Zeichenkette**, oder die Nutzer-Passphrase |
| `salt` | 16 zufällige Bytes |
| `iterations` | 600 000 für neue Container |
| Ergebnis | 32 Byte, als AES-256-GCM-Schlüssel |

**Interop-Falle:** abgeleitet wird aus dem Base64url-*Text* des `linkKey`, nicht
aus den Bytes, die er kodiert. Wer hier dekodiert, erzeugt Container, die der
Browser nicht öffnet.

Das Salt ist **nicht** Teil des Containers. Es wird neben dem Ciphertext als
eigenes Feld `salt` (Base64url) übertragen und gespeichert. Es ist kein
Geheimnis.

Grenzen beim Lesen: unter 180 000 Iterationen ist abzulehnen, über 4 000 000
ebenfalls (Schutz gegen manipulierte Header, die eine Endlosableitung
auslösen). Die Iterationszahl stammt aus dem Header und ist über die AAD
authentifiziert — ein Angreifer kann sie nicht herunterhandeln, ohne dass die
GCM-Prüfung fehlschlägt. Deshalb ist die Erhöhung von 180 000 auf 600 000
abwärtskompatibel.

Passphrasen sind auf 1–4096 Zeichen begrenzt, Salts auf 8–96 Byte.

## 4. Container

Alle Ganzzahlen sind **unsigned, big-endian**.

```text
magic        13 Byte   ASCII "PCPX1-ENC-v2\n"
headerLen     4 Byte   uint32, Länge des Header-JSON
header       n Byte    UTF-8-JSON
chunk[0]
chunk[1]
...
```

Pro Chunk:

```text
cipherLen     4 Byte   uint32, = Klartextlänge + 16
iv           12 Byte   96-Bit-Nonce, pro Chunk frisch zufällig
ciphertext   cipherLen Byte   AES-GCM-Ausgabe, Authentifizierungs-Tag angehängt
```

AES-GCM-Ciphertext ist so lang wie der Klartext; `cipherLen` enthält zusätzlich
das 16-Byte-Tag. Das Tag steht am Ende des Ciphertext-Blocks, nicht in einem
eigenen Feld.

### Header

```json
{"version":2,"alg":"AES-GCM","kdf":"PBKDF2-SHA256","iterations":600000,"chunkSize":5242880,"payloadSize":8,"totalChunks":1,"aad":"PCPX1-CHUNK-AAD-v1"}
```

**Die Feldreihenfolge ist bindend.** Der Header geht byteweise in die AAD jedes
Chunks ein; andere Reihenfolge, anderer Weißraum oder andere
Zahlendarstellung ergeben andere Bytes und damit andere Tags. Ein Erzeuger muss
exakt diese acht Felder in exakt dieser Reihenfolge serialisieren, ohne
Einrückung. `tests/spec-vectors.test.mts` prüft die Zeichenkette wörtlich.

| Feld | Wert |
|---|---|
| `version` | `2` |
| `alg` | `"AES-GCM"` |
| `kdf` | `"PBKDF2-SHA256"` |
| `iterations` | 180 000 … 4 000 000 |
| `chunkSize` | `5242880` (5 MiB), fest |
| `payloadSize` | Gesamtlänge des Klartexts in Byte |
| `totalChunks` | `max(1, ceil(payloadSize / chunkSize))` |
| `aad` | `"PCPX1-CHUNK-AAD-v1"` |

Ein leerer Payload ergibt `payloadSize = 0` und `totalChunks = 1`: ein
authentifizierter Chunk der Länge 0. So trägt auch ein leerer Container ein
Tag über seinen Header, statt ein ungeschütztes Objekt nur aus Header zu sein.

### AAD

Für Chunk `i`:

```text
aad = magic ‖ headerLen ‖ header ‖ uint32be(i)
```

Also die kompletten Container-Header-Bytes vom ersten Magic-Byte bis zum
letzten Header-Byte, gefolgt vom 4-Byte-Chunk-Index. Damit sind Version,
Algorithmen, Iterationszahl, Chunkgröße, Payloadgröße, Chunkanzahl und die
Position jedes Chunks authentifiziert. Umordnen, Abschneiden, Duplizieren oder
Verändern eines Headerfeldes lässt die Entschlüsselung fehlschlagen.

Das Feld `aad` im Header ist nur eine Kennung des AAD-Schemas. Die AAD selbst
ist die obige Byte-Folge, nicht dieser Text.

### Was ein konformer Leser ablehnen muss

- Container über 64 MiB
- Magic ungleich `PCPX1-ENC-v2\n`
- `headerLen` von 0 oder über 16 384
- Header, der kein JSON-Objekt ist
- `version ≠ 2`, `alg ≠ AES-GCM`, `kdf ≠ PBKDF2-SHA256`, `aad ≠ PCPX1-CHUNK-AAD-v1`
- `chunkSize ≠ 5242880`
- `iterations` außerhalb 180 000 … 4 000 000 oder keine sichere Ganzzahl
- `payloadSize` negativ oder keine sichere Ganzzahl
- `totalChunks ≠ max(1, ceil(payloadSize / chunkSize))`
- Gesamtlänge ungleich `headerBytes + payloadSize + totalChunks × 32`
- `cipherLen` ungleich erwartete Chunk-Klartextlänge + 16
- Restbytes hinter dem letzten Chunk
- Summe der entschlüsselten Längen ungleich `payloadSize`

Die Längenprüfungen laufen **vor** der Schlüsselableitung. Sonst kostet ein
manipulierter Container 600 000 PBKDF2-Runden, bevor er verworfen wird — ein
billiger Weg, fremde Rechenzeit zu verbrennen.

Die Prüfungen sind zusätzlich zur GCM-Authentifizierung, nicht statt ihrer.
Authentisch wird ein Container allein durch erfolgreiche Entschlüsselung.

## 5. Payload-Schicht

Innerhalb des entschlüsselten Klartexts:

```text
magic        26 Byte   ASCII "PCPX1-PAYLOAD-METADATA-v1\n"
metaLen       4 Byte   uint32, Länge des Metadaten-JSON (1 … 16 384)
metadata     n Byte    UTF-8-JSON
content      Rest      Nutzdaten
```

```json
{"version":1,"kind":"file","name":"vertrag.pdf","type":"application/pdf","size":12345}
```

`kind` ist `"text"` oder `"file"`. Fehlt das Magic oder ist das JSON ungültig,
behandelt der Leser den gesamten Klartext als Inhalt ohne Metadaten
(`legacy`) — er bricht nicht ab.

Anders als beim Containerheader ist die Feldreihenfolge hier **nicht** bindend:
die Metadaten liegen vollständig im authentifizierten Bereich und werden nach
Namen gelesen.

`size` ist rein informativ und wird bewusst nicht gegen die tatsächliche Länge
geprüft. Ein Erzeuger, der UTF-16-Längen zählt, würde den Inhalt sonst still
auf `legacy` degradieren, ohne dass daraus ein Sicherheitsgewinn entstünde.

### Umgang mit `name` und `type`

Beide stammen vom Absender und sind nach der Entschlüsselung immer noch
Fremdeingabe.

`type` ist gegen eine Erlaubnisliste inerter MIME-Typen zu prüfen; alles andere
wird zu `application/octet-stream`. Insbesondere `text/html`,
`application/xhtml+xml`, `image/svg+xml` und alle `*+xml` sind
**auszuschließen** — sie sind skriptfähig, und ein über `URL.createObjectURL()`
geöffnetes Dokument läuft im Origin des Empfängers.

Der erzeugte File bekommt immer den neutralen Typ; der deklarierte Typ dient
nur der Anzeige.

`name` ist zu bereinigen: Pfadtrenner, Windows-Sonderzeichen, Steuerzeichen und
bidirektionale Steuerzeichen (U+202A–U+202E, U+2066–U+2069) ersetzen, führende
Punkte entfernen, auf 180 Zeichen kürzen, reservierte Windows-Gerätenamen
(`CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`) mit einem Unterstrich
präfixen. Bleibt nichts übrig: `decrypted_secret`.

## 6. Testvektoren

`tests/vectors/pcpx1-enc-v2.json` enthält sieben Vektoren: leerer Payload, ein
Byte, UTF-8 mit Umlauten und Emoji, Sonderzeichen in der Passphrase, die
Iterations-Untergrenze, genau ein voller Chunk, zwei Chunks mit angebrochenem
zweiten.

Jeder Vektor führt Passphrase, Salt, Iterationszahl, den abgeleiteten Schlüssel,
die verwendeten IVs sowie Größe und SHA-256 des Containers. Die beiden
Mehr-Megabyte-Vektoren liegen nicht im Volltext in der Datei; ihr Klartext ist
über die Regel `byte[i] = (i × 31 + 7) mod 256` reproduzierbar.

Der abgeleitete Schlüssel liegt bei, damit eine neue Implementierung ihre
PBKDF2-Stufe unabhängig von AES prüfen kann.

Erzeugt werden die Vektoren von `tools/spec/build-vectors.mjs` — bewusst **ohne**
das SDK, nur mit `node:crypto`. Würde der Generator `encryptFile` aufrufen,
prüfte der Test das SDK gegen sich selbst und jeder Fehler in diesem Dokument
bliebe unsichtbar.

`tests/spec-vectors.test.mts` läuft in beide Richtungen: das SDK entschlüsselt
jeden Vektor, und ein unabhängiger Parser zerlegt, was `encryptFile` schreibt.
Eine Richtung allein genügt nicht — sie würde einen zu strengen bzw. einen zu
laxen Leser durchwinken.

## 7. Nicht Gegenstand dieses Dokuments

- TrustKey, Empfängerfreigabe, Geräteregistrierung — eigene Formate
- HTTP-Verträge der API v1
- Aufbewahrung, Ablauf und Einmal-Lesen — Serververhalten, nicht Format
- `PCPX-SW-ENC-v1` (Windows Secure Wrapper) und `SPR-VAULT-v1` (Vault): eigene
  Formate, nicht kompatibel

## 8. Für neue Implementierungen

1. PBKDF2 gegen `derivedKeyB64u` der Vektoren prüfen — scheitert das, ist alles
   Weitere sinnlos.
2. Container der Vektoren entschlüsseln.
3. Eigene Container erzeugen und Größe sowie SHA-256 gegen die Vektoren
   vergleichen. Bei gleichen IVs müssen sie Byte für Byte übereinstimmen.
4. Jeden Fall aus „Was ein konformer Leser ablehnen muss" mit einem bewusst
   kaputten Container prüfen.

Erst wenn alle vier Schritte sitzen, darf eine Implementierung
`PCPX1-ENC-v2` in ihre Container schreiben. Eine Kennung zu setzen, ohne die
Bytes zu treffen, ist schlimmer als ein eigenes Format zu wählen — es behauptet
eine Interoperabilität, die es nicht gibt.
