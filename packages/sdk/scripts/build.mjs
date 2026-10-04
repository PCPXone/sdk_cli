import fs from 'node:fs';
import path from 'node:path';
import { build } from 'esbuild';

// A real JS file avoids shell-dependent quoting of template literals.
for (const file of fs.readdirSync('dist')) {
  if (!file.endsWith('.d.ts')) continue;
  const target = `dist/${file}`;
  fs.writeFileSync(target, fs.readFileSync(target, 'utf8').replace(/from '\.\/([^.]+)\.ts'/g, "from './$1.js'"));
}
await build({ entryPoints: ['src/index.ts'], bundle: true, format: 'esm', platform: 'neutral', target: 'es2022', outfile: 'dist/index.js' });

// Spezifikation und Testvektoren wandern ins Paket.
//
// Fuer eine Krypto-Bibliothek ist "wo ist das Format beschrieben?" eine
// berechtigte Frage, und ein Verweis auf eine Repo-Datei hilft niemandem, der
// nur `npm install` gemacht hat — das Repo ist nicht oeffentlich. Beides liegt
// deshalb im Tarball. Erzeugte Dateien, nicht von Hand pflegen.
const copies = [
  ['../../docs/PCPX1-ENC-v2.md', 'SPEC.md'],
  ['../../tests/vectors/pcpx1-enc-v2.json', 'vectors/pcpx1-enc-v2.json'],
];
for (const [from, to] of copies) {
  if (!fs.existsSync(from)) throw new Error(`Spezifikationsdatei fehlt: ${from}`);
  fs.mkdirSync(path.dirname(to), { recursive: true });
  fs.copyFileSync(from, to);
}
console.log(`SDK: ${copies.length} Spezifikationsdateien uebernommen.`);
