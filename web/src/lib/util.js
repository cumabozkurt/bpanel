import { get } from 'svelte/store';
import { te, translate } from './i18n/index.js';
import { toast } from './stores.js';

// API field names -> label keys, for errors that name the offending field (round 2: {error, field, max})
const FIELD_LABELS = {
	disk_mb: 'pkg.disk', bandwidth_mb: 'pkg.bandwidth', max_domains: 'pkg.domains', max_subdomains: 'pkg.subdomains', max_aliases: 'pkg.aliases',
	max_email: 'pkg.email', mail_quota_mb: 'pkg.mail_quota', max_db: 'pkg.db', max_ftp: 'pkg.ftp', cpu_percent: 'pkg.cpu', memory_mb: 'pkg.memory',
	max_tasks: 'pkg.tasks', quota_mb: 'email.quota', max_accounts: 'newacc.max_accounts', reseller_disk_mb: 'newacc.reseller_disk', name: 'pkg.name',
	username: 'acc.username', domain: 'acc.domain', docroot: 'domains.docroot', dir: 'ftp.directory', login: 'ftp.login', local: 'email.address',
	source: 'fwd.address', command: 'cron.command', reason: 'acc.reason', password: 'common.password', email: 'newacc.email'
};
export function fieldLabel(f) {
	const k = FIELD_LABELS[f];
	return k ? translate(k) : f;
}

/** Translated error message for an ApiError (never the raw English server text). */
export function errText(e) {
	const code = e?.code ?? 'internal_error';
	if (code === 'limit_reached' && e?.message) {
		const what = translate('limits.' + e.message);
		return translate('errors.limit_reached_what', { what: what === 'limits.' + e.message ? e.message : what });
	}
	const field = e?.data?.field || (code === 'reseller_unlimited_not_allowed' ? e?.message : '');
	if (code === 'too_long') return translate('errors.too_long', { max: e?.data?.max ?? '?' }) + (field ? ' (' + fieldLabel(field) + ')' : '');
	const msg = get(te)(code);
	if (code === 'shield_blocked') { const d = e?.data?.details; const sig = (d?.detections ?? []).map((x) => x.signature).join(', '); return msg + (d?.file ? ' ' + d.file : '') + (sig ? ' (' + sig + ')' : ''); } // v0.4 shield
	return field ? msg + ' (' + fieldLabel(field) + ')' : msg;
}

export function showErr(e) {
	toast(errText(e), 'error', 6000);
}

/** Translated text for a structured warning {code, area, detail} (handoff-ui H-6). */
export function warnText(w) {
	if (typeof w === 'string') return w; // pre-0.2 API
	const key = 'warnings.' + w.code;
	const s = translate(key, { detail: w.detail ?? '' });
	return s === key ? translate('warnings.generic', { code: w.code, detail: w.detail ?? '' }) : s;
}

/** Shows every warning of a successful response as a non-blocking notice. */
export function showWarnings(res) {
	for (const w of res?.warnings ?? []) toast(warnText(w), 'warn', 8000);
}

export function ok(key, params) {
	toast(translate(key, params), 'ok');
}

/** confirm() with translated text (native dialog keeps it accessible and simple). */
export function ask(key, params) {
	return window.confirm(translate(key, params));
}

export function qs(name) {
	return new URLSearchParams(location.search).get(name);
}

/** Audit action code -> translated label ("account.create" -> "Account created"). */
export function auditLabel(action) {
	if (!action) return '—';
	const key = 'audit_actions.' + action.replace(/\./g, '_');
	const s = translate(key);
	if (s !== key) return s;
	const [area, ...rest] = action.split('.');
	const a = translate('audit_actions.' + area);
	return a !== 'audit_actions.' + area ? a + ' · ' + rest.join('.') : action;
}


/** Normalise a list response: the API returns bare arrays for most lists, a few wrap them in {items} or {accounts}. */
export function asList(v) {
	if (Array.isArray(v)) return v;
	return v?.items ?? v?.accounts ?? [];
}
