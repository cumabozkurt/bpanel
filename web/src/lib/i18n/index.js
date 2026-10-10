// BOZKURT PANEL i18n.
// Every JSON file in ./locales is a language; its "_meta" block names it.
// To add a language: copy en.json to xx.json, translate the values, rebuild.
// Lookup order: active language -> English -> the key itself.
import { derived, writable, get } from 'svelte/store';

const files = import.meta.glob('./locales/*.json', { eager: true });

/** @type {Record<string, Record<string, any>>} */
const dicts = {};
for (const [path, mod] of Object.entries(files)) {
	const code = path.match(/([a-zA-Z-]+)\.json$/)?.[1];
	if (code) dicts[code] = /** @type {any} */ (mod).default ?? mod;
}

export const FALLBACK = 'en';

/** Available languages, sorted with English first. */
export const languages = Object.keys(dicts)
	.map((code) => ({ code, name: dicts[code]?._meta?.name ?? code, dir: dicts[code]?._meta?.dir ?? 'ltr' }))
	.sort((a, b) => (a.code === FALLBACK ? -1 : b.code === FALLBACK ? 1 : a.name.localeCompare(b.name)));

function lookup(dict, key) {
	let cur = dict;
	for (const part of key.split('.')) {
		if (cur == null || typeof cur !== 'object') return undefined;
		cur = cur[part];
	}
	return typeof cur === 'string' ? cur : undefined;
}

export function resolveLang(...candidates) {
	for (const c of candidates) {
		if (!c) continue;
		if (dicts[c]) return c;
		const base = c.split('-')[0];
		if (dicts[base]) return base;
	}
	return FALLBACK;
}

const stored = typeof localStorage !== 'undefined' ? localStorage.getItem('bp_lang') : null;
export const locale = writable(resolveLang(stored, FALLBACK));

locale.subscribe((l) => {
	if (typeof document !== 'undefined') {
		document.documentElement.lang = l;
		document.documentElement.dir = dicts[l]?._meta?.dir ?? 'ltr';
	}
});

export function setLocale(code, persist = true) {
	const l = resolveLang(code);
	locale.set(l);
	if (persist && typeof localStorage !== 'undefined') localStorage.setItem('bp_lang', l);
}

function format(str, params) {
	if (!params) return str;
	return str.replace(/\{(\w+)\}/g, (m, k) => (params[k] !== undefined ? String(params[k]) : m));
}

const pluralRules = {};
/** CLDR plural category for n in lang ('one', 'other', …). */
export function pluralCategory(n, lang = get(locale)) {
	const tag = lang === 'tr' ? 'tr-TR' : lang;
	try { return (pluralRules[tag] ??= new Intl.PluralRules(tag)).select(n); } catch { return n === 1 ? 'one' : 'other'; }
}

/**
 * translate(key, params, lang). Plurals (R2-UX-32): when params.n is a number and the dictionary has
 * key_<category> (key_one, key_other, …), that form is used; otherwise the plain key. Every plural
 * family keeps its plain key as the fallback, so callers never change.
 */
export function translate(key, params, lang = get(locale)) {
	let s;
	if (params && typeof params.n === 'number') {
		s = lookup(dicts[lang], key + '_' + pluralCategory(params.n, lang)) ?? lookup(dicts[lang], key + '_other');
		if (s === undefined && lang !== FALLBACK) s = lookup(dicts[FALLBACK], key + '_' + pluralCategory(params.n, FALLBACK));
	}
	s ??= lookup(dicts[lang], key) ?? lookup(dicts[FALLBACK], key) ?? key;
	return format(s, params);
}

/** tp(key, n, params): explicit plural lookup (same rules as translate with params.n). */
export function tp(key, n, params = {}, lang = get(locale)) {
	return translate(key, { ...params, n }, lang);
}

/** $t('key', {param}) in components */
export const t = derived(locale, (l) => (key, params) => translate(key, params, l));

/**
 * Error code -> message in the active language. Unknown codes get a translated generic
 * message that names the code; the server's raw (English) message is never shown.
 */
export const te = derived(locale, (l) => (code) => {
	const c = code || 'internal_error';
	const s = lookup(dicts[l], 'errors.' + c) ?? lookup(dicts[FALLBACK], 'errors.' + c);
	if (s) return s;
	if (/^http_\d+$/.test(c)) return translate('errors.http_generic', { status: c.slice(5) }, l);
	if (/^invalid_/.test(c)) return translate('errors.invalid_generic', { code: c }, l);
	return translate('errors.unknown', { code: c }, l);
});

/** Locale-aware number/size/date helpers */
export const fmt = derived(locale, (l) => {
	const tag = l === 'tr' ? 'tr-TR' : l;
	return {
		num: (n) => new Intl.NumberFormat(tag).format(n ?? 0),
		bytes: (b) => {
			if (!b) return '0 B';
			const u = ['B', 'KB', 'MB', 'GB', 'TB'];
			let i = 0;
			let v = b;
			while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
			return new Intl.NumberFormat(tag, { maximumFractionDigits: v < 10 && i > 0 ? 1 : 0 }).format(v) + ' ' + u[i];
		},
		date: (unix) => (unix ? new Intl.DateTimeFormat(tag, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(unix * 1000)) : '—'),
		dateISO: (iso) => (iso ? new Intl.DateTimeFormat(tag, { dateStyle: 'medium' }).format(new Date(iso)) : '—'),
		duration: (sec) => {
			const d = Math.floor((sec ?? 0) / 86400), h = Math.floor(((sec ?? 0) % 86400) / 3600), m = Math.floor(((sec ?? 0) % 3600) / 60);
			if (d > 0) return translate('units.days_hours', { d, h }, l);
			if (h > 0) return translate('units.hours_minutes', { h, m }, l);
			return translate('units.minutes', { m }, l);
		}
	};
});
