import { writable, get } from 'svelte/store';
import { api, setCSRF } from './api.js';
import { setLocale, resolveLang } from './i18n/index.js';
import { applyServerLimits } from './validate.js';
import { noteMeta } from './limits.js';

export const meta = writable(null); // /meta
export const session = writable(null); // /auth/me
export const toasts = writable([]);
export const paletteOpen = writable(false);
export const pageTitle = writable(''); // current page heading, for document.title (R2-UX-24)

let tid = 0;
export function toast(message, kind = 'ok', ms = 4200) {
	const id = ++tid;
	toasts.update((l) => [...l, { id, message, kind }]);
	setTimeout(() => toasts.update((l) => l.filter((x) => x.id !== id)), ms);
}

export function applyTheme(theme) {
	const t = theme === 'system' ? (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light') : theme || 'light';
	document.documentElement.dataset.theme = t;
	localStorage.setItem('bp_theme', theme || 'light');
}

export async function loadMeta() {
	const m = await api.get('/meta');
	meta.set(m);
	applyServerLimits(m.limits);
	noteMeta(m);
	if (!localStorage.getItem('bp_lang')) setLocale(m.default_lang, false);
	return m;
}

export async function loadSession() {
	try {
		const me = await api.get('/auth/me', { noRedirect: true });
		setCSRF(me.csrf);
		session.set(me);
		const m = get(meta);
		setLocale(resolveLang(me.user.lang, localStorage.getItem('bp_lang'), me.default_lang, m?.default_lang), false);
		applyTheme(me.user.theme);
		return me;
	} catch {
		session.set(null);
		return null;
	}
}

export async function logout() {
	try { await api.post('/auth/logout'); } catch {}
	session.set(null);
	setCSRF('');
}
