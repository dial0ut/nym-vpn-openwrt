'use strict';
// Parse every LuCI module under htdocs/ (top-level `return` makes
// `node --check` reject them, so compile each as a function body instead),
// resolve its require header against the tree, and parse the rpcd ACL.
const fs = require('fs');
const path = require('path');
const { scanRequires, RESOURCES, moduleFile } = require('./luci-env');

const BUILTINS = ['baseclass', 'dom', 'poll', 'ui', 'rpc', 'view', 'form', 'uci', 'fs', 'network'];

function walk(dir, out) {
  for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, ent.name);
    if (ent.isDirectory()) walk(p, out);
    else if (ent.name.endsWith('.js')) out.push(p);
  }
  return out;
}

let failures = 0;
const files = walk(RESOURCES, []).sort();
for (const file of files) {
  const rel = path.relative(RESOURCES, file);
  const src = fs.readFileSync(file, 'utf8');
  try {
    new Function(src);
  } catch (e) {
    failures++;
    console.log('FAIL parse   ' + rel + ': ' + e.message);
    continue;
  }
  const missing = scanRequires(src)
    .map((d) => d.name)
    .filter((n) => BUILTINS.indexOf(n) === -1 && !fs.existsSync(moduleFile(n)));
  if (missing.length) {
    failures++;
    console.log('FAIL require ' + rel + ': unresolved ' + missing.join(', '));
    continue;
  }
  console.log('ok   ' + rel);
}

const acl = path.resolve(__dirname, '..', 'root', 'usr', 'share', 'rpcd', 'acl.d', 'luci-app-nym-vpn.json');
try {
  JSON.parse(fs.readFileSync(acl, 'utf8'));
  console.log('ok   ' + path.relative(path.resolve(__dirname, '..'), acl));
} catch (e) {
  failures++;
  console.log('FAIL json ' + acl + ': ' + e.message);
}

console.log(files.length + ' modules parsed, ' + failures + ' failure(s)');
process.exit(failures ? 1 : 0);
