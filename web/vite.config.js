import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';
import fs from 'node:fs';
import path from 'node:path';

// Build perf (round 2): `import { X } from '@lucide/svelte'` makes Vite transform all ~4000 icon
// modules of the barrel before tree-shaking them away (≈1.5 GB peak RSS, killed on small build
// hosts). This rewrites each such import to direct per-icon imports, so only the ~90 icons the
// panel uses are processed. Output is identical; the build is faster and needs far less memory.
function lucideDirect() {
	const dist = path.resolve('node_modules/@lucide/svelte/dist');
	const map = new Map();
	for (const f of ['icons/index.js', 'aliases/aliases.js']) {
		const file = path.join(dist, f);
		if (!fs.existsSync(file)) continue;
		for (const m of fs.readFileSync(file, 'utf8').matchAll(/default as (\w+) \} from '(?:\.\.\/icons\/|\.\/)([a-z0-9-]+)(?:\.svelte|\.js)'/g)) map.set(m[1], m[2]);
	}
	const re = /import\s*\{([^}]+)\}\s*from\s*['"]@lucide\/svelte['"];?/g;
	return {
		name: 'bpanel-lucide-direct',
		enforce: 'pre',
		transform(code, id) {
			if (!map.size || id.includes('node_modules') || !/\.(svelte|js)$/.test(id) || !code.includes('@lucide/svelte')) return null;
			let ok = true;
			const out = code.replace(re, (all, names) => {
				const parts = names.split(',').map((s) => s.trim()).filter(Boolean);
				const lines = [];
				for (const p of parts) {
					const [name, local = name] = p.split(/\s+as\s+/).map((s) => s.trim());
					const file = map.get(name);
					if (!file) { ok = false; return all; }
					lines.push(`import ${local} from '@lucide/svelte/icons/${file}';`);
				}
				return lines.join('\n');
			});
			return ok && out !== code ? { code: out, map: null } : null;
		}
	};
}

export default defineConfig({
	plugins: [lucideDirect(), sveltekit()],
	server: { proxy: { '/api': 'http://127.0.0.1:2083' } }
});
