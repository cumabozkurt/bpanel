// Client-side mirrors of the backend rules in internal/validate and the agent.
// Every function returns null when the value is fine, or an i18n key (errors.* or val.*)
// describing the problem, so the message is always in the user's language.

// --- passwords: validate.Password ---------------------------------------------
export function passwordProblem(s) {
	if (!s) return 'val.required';
	if (s.length < 10) return 'errors.password_too_short';
	if (s.length > 256) return 'errors.password_too_long';
	if (/[:\r\n\0]/.test(s)) return 'errors.password_bad_char';
	const classes = [/[a-z]/, /[A-Z]/, /[0-9]/].filter((r) => r.test(s)).length;
	if (classes < 2) return 'errors.password_too_weak';
	return null;
}

// --- usernames: validate.Username (reserved list kept in sync by hand; see audit/handoff-ui.md) ---
export const RESERVED_USERNAMES = new Set(
	('root bin daemon adm lp sync shutdown halt mail news uucp operator games ftp nobody www wwwdata apache nginx mysql ' +
		'postfix dovecot pdns redis rspamd bpanel bpadmin admin sshd systemd messagebus syslog test all virtfs vmail clamav ' +
		'postgres named polkitd chrony').split(' ')
);
export const USERNAME_RE = /^[a-z][a-z0-9]{1,15}$/;
export function usernameProblem(s) {
	if (!USERNAME_RE.test(s)) return 'errors.invalid_username';
	if (RESERVED_USERNAMES.has(s) || (s.startsWith('bp') && s.length <= 3)) return 'errors.reserved_username';
	return null;
}

// --- domains: validate.Domain (after IDN -> punycode) ---------------------------
const LABEL_RE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
/** Convert a typed domain (may contain ç, ş, … or a URL) to its ASCII/punycode form. */
export function toAsciiDomain(input) {
	let s = String(input ?? '').trim().toLowerCase().replace(/^[a-z]+:\/\//, '').replace(/[/?#].*$/, '').replace(/\.$/, '');
	if (!s) return '';
	if (/[^\x00-\x7f]/.test(s)) {
		try { s = new URL('http://' + s).hostname; } catch { /* keep as typed; the check below fails it */ }
	}
	return s;
}
export function domainProblem(s) {
	if (!s || s.length < 3 || s.length > 253 || s.endsWith('.')) return 'errors.invalid_domain';
	const parts = s.split('.');
	if (parts.length < 2 || !parts.every((p) => LABEL_RE.test(p))) return 'errors.invalid_domain';
	if (/^[0-9.]+$/.test(s)) return 'errors.invalid_domain';
	return null;
}
export const LABEL_PATTERN = '[a-z0-9]([a-z0-9\\-]{0,61}[a-z0-9])?';

// --- email local part: validate.EmailLocal ---------------------------------------
export const EMAIL_LOCAL_PATTERN = '[a-z0-9][a-z0-9._+\\-]{0,62}';
export function emailLocalProblem(s) {
	if (!new RegExp('^' + EMAIL_LOCAL_PATTERN + '$').test(s) || s.includes('..')) return 'errors.invalid_email_local';
	return null;
}

// --- FTP login: API (EmailLocal, no '+') and agent (^[a-z0-9][a-z0-9._-]{0,31}@) ---
export const FTP_LOGIN_PATTERN = '[a-z0-9][a-z0-9._\\-]{0,31}';
export function ftpLoginProblem(s) {
	if (!new RegExp('^' + FTP_LOGIN_PATTERN + '$').test(s) || s.includes('..')) return 'errors.invalid_ftp_login';
	return null;
}

// --- databases: validate.DBName / DBUser ------------------------------------------
export const DB_SUFFIX_PATTERN = '[a-z0-9_]+';
/** Max suffix length for a DB user: total (prefix + suffix) <= 32. */
export const dbUserMax = (prefix) => Math.max(1, Math.min(40, 32 - (prefix?.length ?? 0)));
/** Max suffix length for a DB name: suffix <= 40, total <= 64. */
export const dbNameMax = (prefix) => Math.max(1, Math.min(40, 64 - (prefix?.length ?? 0)));

// --- cron: field-by-field check with ranges, steps, lists and names ----------------
const MONTHS = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec'];
const DAYS = ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat'];
export const CRON_FIELDS = {
	minute: { min: 0, max: 59 },
	hour: { min: 0, max: 23 },
	dom: { min: 1, max: 31 },
	month: { min: 1, max: 12, names: MONTHS, base: 1 },
	dow: { min: 0, max: 7, names: DAYS, base: 0 }
};

function cronValue(tok, spec) {
	if (/^\d+$/.test(tok)) return Number(tok);
	const i = spec.names?.indexOf(tok.toLowerCase()) ?? -1;
	return i >= 0 ? i + spec.base : NaN;
}

/** Returns null or 'val.cron_field' (with the allowed range in the message params). */
export function cronFieldProblem(value, field) {
	const spec = CRON_FIELDS[field];
	const v = String(value ?? '').trim();
	if (!v) return 'val.required';
	if (v.length > 40 || !/^[0-9*/,\-A-Za-z]+$/.test(v)) return 'val.cron_field';
	for (const item of v.split(',')) {
		const m = item.match(/^([^/]+)(?:\/(\d+))?$/);
		if (!m) return 'val.cron_field';
		const [, range, step] = m;
		if (step !== undefined && (Number(step) < 1 || Number(step) > spec.max)) return 'val.cron_field';
		if (range === '*') continue;
		const ends = range.split('-');
		if (ends.length > 2) return 'val.cron_field';
		const nums = ends.map((x) => cronValue(x, spec));
		if (nums.some((n) => Number.isNaN(n) || n < spec.min || n > spec.max)) return 'val.cron_field';
		if (nums.length === 2 && nums[0] > nums[1]) return 'val.cron_range_order';
	}
	return null;
}

export function cronCommandProblem(s) {
	if (!s || !s.trim()) return 'val.required';
	if (s.length > 1000 || /[\r\n\0]/.test(s)) return 'errors.invalid_cron_command';
	return null;
}

// --- server-advertised limits (GET /meta -> limits, when the backend provides them) ---------
export const serverLimits = { reservedDbSuffixes: new Set(['pma']), uploadMaxFile: 0, uploadMaxRequest: 0 };
/** Merge what the API advertises so the UI never accepts what the backend will reject. */
export function applyServerLimits(limits) {
	if (!limits) return;
	for (const u of limits.username?.reserved ?? []) RESERVED_USERNAMES.add(u);
	for (const s of limits.db_user?.reserved_suffixes ?? []) serverLimits.reservedDbSuffixes.add(s);
	if (limits.upload_max_file > 0) serverLimits.uploadMaxFile = limits.upload_max_file;
	if (limits.upload_max_request > 0) serverLimits.uploadMaxRequest = limits.upload_max_request;
	applyRound2Limits(limits);
}
export function dbUserSuffixProblem(s) {
	return serverLimits.reservedDbSuffixes.has(s) ? 'errors.reserved_db_user' : null;
}

// --- round 2 (R2-UX-10…21): length, IDN, paths, file names, DNS ------------------------------

/** Length in characters as the user counts them (code points, not UTF-16 units). */
export const charLen = (s) => [...String(s ?? '')].length;
export const byteLen = (s) => new TextEncoder().encode(String(s ?? '')).length;

/** Whether toAsciiDomain() dropped something (scheme, path, trailing dot): shown in the idn-note line. */
export function domainWasCleaned(input) {
	const s = String(input ?? '').trim().toLowerCase();
	return /^[a-z]+:\/\//.test(s) || /[/?#]/.test(s) || s.endsWith('.');
}
// Emoji, pictographs and symbols are not valid in IDNA2008 domain names; registries refuse them.
const DOMAIN_SYMBOLS = /[\p{Extended_Pictographic}\p{So}\p{Sm}\p{Sk}\p{Cf}\p{Co}]/u;
/** Full check of a typed domain: symbols in the original text, then the ASCII (punycode) form. */
export function typedDomainProblem(input) {
	const raw = String(input ?? '').trim();
	if (!raw) return null;
	if (DOMAIN_SYMBOLS.test(raw)) return 'val.domain_symbols';
	return domainProblem(toAsciiDomain(raw));
}

// docroot / FTP directory: validate.RelPath + DocRoot (segment pattern and private top dirs from /meta)
serverLimits.pathSegment = /^[A-Za-z0-9_-][A-Za-z0-9._-]{0,127}$/;
serverLimits.privateTop = new Set(['backups', 'etc', 'logs', 'mail', 'ssl', 'tmp']);
export function applyRound2Limits(limits) {
	const seg = limits?.docroot?.segment_pattern;
	if (seg) { try { serverLimits.pathSegment = new RegExp(seg); } catch { /* keep the built-in copy */ } }
	for (const d of limits?.docroot?.private_top_dirs ?? []) serverLimits.privateTop.add(d);
}
/** null | 'errors.invalid_docroot_hint'. allowHome: '' (the home itself) is fine (FTP). */
export function relPathProblem(p, { allowHome = false, privateTop = true } = {}) {
	const v = String(p ?? '').trim();
	if (byteLen(v) > 255) return 'errors.invalid_docroot_hint';
	const c = v.replace(/^\/+|\/+$/g, '');
	if (!c) return allowHome ? null : 'errors.invalid_docroot_hint';
	const segs = c.split('/').filter(Boolean);
	if (segs.some((s) => !serverLimits.pathSegment.test(s))) return 'errors.invalid_docroot_hint';
	if (privateTop && serverLimits.privateTop.has(segs[0])) return 'errors.invalid_docroot_hint';
	return null;
}
/** The backend derives the docroot from the domain; one path segment holds at most 128 characters. */
export const DOCROOT_SEGMENT_MAX = 128;

/** File Manager names (R2-UX-16): one segment, not . or .., at most 255 bytes. */
export function fileNameProblem(name) {
	const v = String(name ?? '').trim();
	if (!v) return 'val.required';
	if (v === '.' || v === '..' || v.includes('/') || v.includes('\0')) return 'val.filename';
	if (byteLen(v) > 255) return 'val.filename_long';
	return null;
}

// --- DNS (R2-UX-18/20, G2) ---------------------------------------------------------------------
const DNS_LABEL = /^(\*|[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)$/;
/** Punycode a name (labels may be Turkish/Arabic/…); '' on failure. */
export function asciiName(s) {
	s = String(s ?? '');
	if (!/[^\x00-\x7f]/.test(s)) return s;
	const star = s.startsWith('*.');
	try { const h = new URL('http://' + (star ? 'x.' + s.slice(2) : s)).hostname; return star ? '*.' + h.slice(2) : h; } catch { return ''; }
}
/**
 * Record name typed in the zone editor -> { rel, fqdn, problem }.
 * "" and "@" are the apex; a trailing dot makes the name absolute (FQDN), as in every zone editor.
 */
export function dnsName(input, zone) {
	const v = String(input ?? '').trim().toLowerCase();
	const z = String(zone ?? '').toLowerCase();
	if (DOMAIN_SYMBOLS.test(v)) return { rel: v, fqdn: '', problem: 'val.domain_symbols' };
	if (v === '' || v === '@') return { rel: '', fqdn: z, problem: null };
	let rel;
	if (v.endsWith('.')) {
		const abs = asciiName(v.slice(0, -1));
		if (abs === z) rel = '';
		else if (abs.endsWith('.' + z)) rel = abs.slice(0, -(z.length + 1));
		else return { rel: v, fqdn: abs, problem: 'errors.record_outside_zone' };
	} else {
		rel = asciiName(v);
		if (!rel) return { rel: v, fqdn: '', problem: 'errors.invalid_record_name' };
		if (rel === z) rel = '';
		else if (rel.endsWith('.' + z)) rel = rel.slice(0, -(z.length + 1)); // pasted FQDN without the dot
	}
	if (rel && !rel.split('.').every((l) => DNS_LABEL.test(l))) return { rel, fqdn: '', problem: 'errors.invalid_record_name' };
	const fqdn = rel ? rel + '.' + z : z;
	if (fqdn.length > 253) return { rel, fqdn, problem: 'errors.invalid_record_name' };
	return { rel, fqdn, problem: null };
}
export const IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
export function isIPv6(s) {
	s = String(s ?? '');
	if (!/^[0-9a-f:.]+$/i.test(s) || !s.includes(':')) return false;
	try { new URL('http://[' + s + ']/'); return true; } catch { return false; }
}
const HOST_RE = /^(?=.{1,253}$)[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?(\.[a-z0-9_]([a-z0-9-]{0,61}[a-z0-9])?)*$/i;
export const hostProblem = (s) => (HOST_RE.test(asciiName(String(s ?? '').trim().replace(/\.$/, ''))) ? null : 'val.hostname');
const intIn = (v, lo, hi) => /^\d+$/.test(String(v ?? '').trim()) && Number(v) >= lo && Number(v) <= hi;
/** Per-type check of one structured record (fields as in the zone editor form). */
export function dnsRecordProblem(type, r) {
	switch (type) {
		case 'A': return IPV4_RE.test(String(r.value ?? '').trim()) ? null : 'errors.invalid_ipv4';
		case 'AAAA': return isIPv6(String(r.value ?? '').trim()) ? null : 'errors.invalid_ipv6';
		case 'CNAME': return hostProblem(r.value);
		case 'MX': return !intIn(r.priority, 0, 65535) ? 'val.dns_priority' : hostProblem(r.host);
		case 'SRV': return !intIn(r.priority, 0, 65535) ? 'val.dns_priority' : !intIn(r.weight, 0, 65535) ? 'val.dns_weight' : !intIn(r.port, 0, 65535) ? 'val.dns_port' : String(r.host).trim() === '.' ? null : hostProblem(r.host);
		case 'CAA': return !intIn(r.flag, 0, 255) ? 'val.dns_flag' : !['issue', 'issuewild', 'iodef'].includes(r.tag) ? 'val.dns_tag' : !String(r.value ?? '').trim() ? 'val.required' : /["\\]/.test(r.value) ? 'val.dns_caa_value' : null;
		default: return String(r.value ?? '').trim() ? null : 'val.required';
	}
}
/** Structured fields -> the record's presentation format the API expects. */
export function dnsCompose(type, r) {
	const h = (x) => asciiName(String(x ?? '').trim().replace(/\.$/, ''));
	switch (type) {
		case 'MX': return `${Number(r.priority)} ${h(r.host)}`;
		case 'SRV': return `${Number(r.priority)} ${Number(r.weight)} ${Number(r.port)} ${String(r.host).trim() === '.' ? '.' : h(r.host)}`;
		case 'CAA': return `${Number(r.flag)} ${r.tag} "${String(r.value).trim()}"`;
		case 'CNAME': return h(r.value);
		default: return String(r.value ?? '').trim();
	}
}
/** Record content from the API -> structured fields. */
export function dnsParse(type, c) {
	const s = String(c ?? '').trim();
	const strip = (x) => String(x ?? '').replace(/\.$/, '');
	if (type === 'MX') { const [p, ...h] = s.split(/\s+/); return { priority: p ?? '10', host: strip(h.join(' ')) }; }
	if (type === 'SRV') { const [p, w, port, ...h] = s.split(/\s+/); return { priority: p ?? '0', weight: w ?? '0', port: port ?? '', host: strip(h.join(' ')) }; }
	if (type === 'CAA') { const m = s.match(/^(\d+)\s+(\S+)\s+"?(.*?)"?$/); return m ? { flag: m[1], tag: m[2], value: m[3] } : { flag: '0', tag: 'issue', value: s }; }
	if (type === 'TXT') return { value: s.replace(/^"|"$/g, '').replace(/"\s*"/g, '') };
	if (type === 'CNAME') return { value: strip(s) };
	return { value: s };
}
export const blankRecord = (type) => (type === 'MX' ? { priority: '10', host: '' } : type === 'SRV' ? { priority: '0', weight: '5', port: '', host: '' } : type === 'CAA' ? { flag: '0', tag: 'issue', value: 'letsencrypt.org' } : { value: '' });
