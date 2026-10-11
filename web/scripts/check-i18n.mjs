// i18n gate (run by `pnpm run i18n:check` and `make web`):
//  1. every locale has exactly the keys of en.json (key parity) and no empty values;
//  2. every static key used in the source exists ($t('…'), ok/ask('…'), data-err="…", 'errors.…'/'val.…' literals);
//  3. every tool, group and quick-action id has a name;
//  4. every error code the Go backend can return has a translation (errors.<code>);
//  5. every audit action the backend records has a label (audit_actions.<area>_<verb> or audit_actions.<area>);
//  6. {placeholders} match between English and each translation;
//  7. every App Installer catalogue entry has appx.desc_<id> / appx.post_<id> and its category a name.
import fs from 'node:fs';
import path from 'node:path';
const dir = 'src/lib/i18n/locales';
const flatEntries = (o, p = '') => Object.entries(o).flatMap(([k, v]) => (typeof v === 'object' && v !== null ? flatEntries(v, p + k + '.') : [[p + k, v]]));
const load = (f) => new Map(flatEntries(JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8'))));
const enMap = load('en.json');
const en = new Set(enMap.keys());
let bad = 0;
const problem = (m) => { console.log(m); bad++; };
const ph = (s) => [...String(s).matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort().join(',');

for (const f of fs.readdirSync(dir).filter((f) => f.endsWith('.json'))) {
	const m = load(f);
	for (const k of en) if (!m.has(k)) problem(`${f}: missing ${k}`);
	for (const [k, v] of m) {
		if (!en.has(k)) problem(`${f}: extra ${k}`);
		else if (v === '' && !k.startsWith('_meta')) problem(`${f}: empty ${k}`);
		else if (f !== 'en.json' && !k.startsWith('_meta') && ph(v) !== ph(enMap.get(k))) problem(`${f}: placeholders differ for ${k} ({${ph(enMap.get(k))}} vs {${ph(v)}})`);
	}
}

const walk = (d) => fs.readdirSync(d, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(path.join(d, e.name)) : [path.join(d, e.name)]));
const used = new Set();
for (const f of walk('src')) {
	if (!/\.(svelte|js)$/.test(f) || f.includes('/locales/')) continue;
	const s = fs.readFileSync(f, 'utf8');
	for (const m of s.matchAll(/\$t\(\s*'([a-z0-9_.]+)'/g)) used.add(m[1]);
	for (const m of s.matchAll(/(?:\bok|\bask|translate)\(\s*'([a-z0-9_.]+)'/g)) used.add(m[1]);
	for (const m of s.matchAll(/data-err="([a-z0-9_.]+)"/g)) used.add(m[1]);
	for (const m of s.matchAll(/'((?:errors|val)\.[a-z0-9_]+)'/g)) used.add(m[1]);
	for (const m of s.matchAll(/\['(db\.wstep_[a-z]+)'/g)) used.add(m[1]);
}
for (const k of used) if (!en.has(k) && !k.endsWith('.') && !k.endsWith('_') && k.includes('.')) problem(`source uses missing key ${k}`);

// dynamic families: every tool and group id in tools.js needs a name
const tools = fs.readFileSync('src/lib/tools.js', 'utf8');
const groupIds = [...tools.matchAll(/\{ id: '([a-z_]+)', icon: \w+, (?:adminOnly: true, )?tools:/g)].map((m) => m[1]);
const toolIds = [...tools.matchAll(/\{ id: '([a-z_]+)', icon: \w+, (?:to:|soon:|action:|href:)/g)].map((m) => m[1]);
for (const g of groupIds) if (!en.has('groups.' + g)) problem('missing groups.' + g);
for (const t of toolIds) if (!en.has('tools.' + t)) problem('missing tools.' + t);
const pal = fs.readFileSync('src/lib/components/CommandPalette.svelte', 'utf8');
for (const m of pal.matchAll(/id: '(qa_[a-z_]+)'/g)) if (!en.has('palette.' + m[1])) problem('missing palette.' + m[1]);

// backend error codes and audit actions (skipped when the Go tree is not next to web/)
const goRoot = path.resolve('..', 'internal');
let codes = new Set(), actions = new Set();
if (fs.existsSync(goRoot)) {
	const goFiles = walk(goRoot).filter((f) => f.endsWith('.go') && !f.endsWith('_test.go'));
	const patterns = [
		/\b(?:bad|badMsg|conflict)\(\s*"([a-z0-9_]+)"/g,
		/Code:\s*"([a-z0-9_]+)"/g,
		/\berrf\(\s*"([a-z0-9_]+)"/g,
		/\bfail\(\s*"([a-z0-9_]+)"/g,
		/errors\.New\(\s*"([a-z0-9_]+)"\)/g,
		/fmt\.Errorf\(\s*"([a-z0-9_]+)"\)/g
	];
	for (const f of goFiles) {
		const s = fs.readFileSync(f, 'utf8');
		for (const re of patterns) for (const m of s.matchAll(re)) if (!m[1].endsWith("_") && (m[1].includes("_") || ["refused", "forbidden"].includes(m[1]))) codes.add(m[1]);
		// settings: bad("invalid_" + k) for each settings key
		if (/bad\("invalid_" \+ k\)/.test(s)) for (const m of s.matchAll(/set\("([a-z_]+)", in\./g)) codes.add('invalid_' + m[1]);
		for (const m of s.matchAll(/\.audit\([^,]+,\s*"([a-z_]+)\.([a-z_]*)"/g)) actions.add(m[2] ? m[1] + '_' + m[2] : m[1]);
	}
	for (const c of codes) if (!en.has('errors.' + c)) problem('backend error code without translation: errors.' + c);
	// structured warnings (internal/api/warnings.go: Warn* = "code")
	const wgo = path.join(goRoot, 'api', 'warnings.go');
	if (fs.existsSync(wgo)) for (const m of fs.readFileSync(wgo, 'utf8').matchAll(/\bWarn[A-Za-z]+\s*=\s*"([a-z0-9_]+)"/g)) if (!en.has('warnings.' + m[1])) problem('warning code without translation: warnings.' + m[1]);
	// generated catalogue (internal/api/errcodes.go) must be covered too
	const ego = path.join(goRoot, 'api', 'errcodes.go');
	if (fs.existsSync(ego)) for (const m of fs.readFileSync(ego, 'utf8').matchAll(/^\t"([a-z0-9_]+)",$/gm)) { codes.add(m[1]); if (!en.has('errors.' + m[1])) problem('catalogued error code without translation: errors.' + m[1]); }
	for (const a of actions) if (!en.has('audit_actions.' + a) && !en.has('audit_actions.' + a.split('_')[0])) problem('audit action without label: audit_actions.' + a);
	// App Installer catalogue: every app has a translated description and next steps, every category a name
	const cgo = path.join(goRoot, 'appx', 'catalog.go');
	if (fs.existsSync(cgo)) {
		const cs = fs.readFileSync(cgo, 'utf8');
		for (const m of cs.matchAll(/\{ID: "([a-z0-9]+)"/g)) for (const k of ['desc_', 'post_']) if (!en.has('appx.' + k + m[1])) problem('catalogue app without text: appx.' + k + m[1]);
		for (const m of cs.matchAll(/Category: "([a-z]+)"/g)) if (!en.has('appx.cat_' + m[1])) problem('catalogue category without name: appx.cat_' + m[1]);
	}
}

console.log(`checked ${groupIds.length} groups, ${toolIds.length} tools, ${codes.size} backend error codes, ${actions.size} audit actions`);
console.log(bad ? `${bad} problem(s)` : 'i18n OK: ' + en.size + ' keys');
process.exit(bad ? 1 : 0);
