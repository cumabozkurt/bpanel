// G1 — limit semantics as in WHM: every limit has an explicit "Unlimited" checkbox and 0 means none.
//
// API contract (round 2, backend): a limit of null or -1 is unlimited, 0 is zero.
// Older servers (<= 0.2.0) read 0 as unlimited and reject negative numbers (invalid_limit /
// invalid_quota). The UI writes the new contract first; if the server rejects a body that contains
// -1 it retries once in the old encoding and remembers that for the session. Evidence for the new
// contract: /meta.limits.unlimited === -1 (or /meta.unlimited === -1), any null/negative limit read
// from the API, or a successful write that contained -1.
import { writable, get } from 'svelte/store';
import { ApiError } from './api.js';

export const UNLIMITED = -1;
/** 'unknown' | 'new' | 'legacy' */
export const limitContract = writable('unknown');

export function noteMeta(meta) {
	if (meta?.limits?.limit_values?.unlimited === -1 || meta?.limits?.unlimited === -1 || meta?.unlimited === -1) limitContract.set('new');
}
/** Call with rows read from the API; a null/negative limit proves the new contract. */
export function noteValues(rows, keys) {
	if (get(limitContract) === 'new') return;
	for (const r of rows ?? []) for (const k of keys) if (r && k in r && (r[k] === null || r[k] < 0)) { limitContract.set('new'); return; }
}
/** Until the server is known to speak the new contract, a 0 read from it still means unlimited. */
export function isUnlimited(v) {
	if (v === null || v === undefined || v < 0) return true;
	return v === 0 && get(limitContract) !== 'new';
}
/** API value -> { unl, n } for the form. */
export function fromApi(v, fallback = 1) {
	return isUnlimited(v) ? { unl: true, n: fallback } : { unl: false, n: v };
}
/** Form value -> API value (new contract). */
export function toApi(f) {
	return f.unl ? UNLIMITED : Number(f.n);
}
/** Display helper: ∞ or the number with an optional unit. */
export function showLimit(v, unit = '') {
	return isUnlimited(v) ? '∞' : v + (unit ? ' ' + unit : '');
}

const LEGACY_REJECT = ['invalid_limit', 'invalid_limits', 'invalid_quota', 'invalid_json', 'invalid_request'];
/**
 * Send a body with limits. keys: the limit fields in body. On an old server the -1 values are
 * re-encoded as 0; an explicit 0 ("none") cannot be expressed there and is refused with
 * limits_zero_unsupported before anything is saved.
 */
export async function sendWithLimits(send, body, keys) {
	const zeroUsed = keys.some((k) => body[k] === 0);
	const unlUsed = keys.some((k) => body[k] === UNLIMITED);
	if (get(limitContract) === 'legacy') return send(legacyBody(body, keys, zeroUsed));
	// cannot tell yet whether this server reads 0 as none or as unlimited: refuse rather than guess
	if (get(limitContract) === 'unknown' && zeroUsed && !unlUsed) throw new ApiError(400, 'limits_zero_unsupported');
	try {
		const r = await send(body);
		if (unlUsed) limitContract.set('new');
		return r;
	} catch (e) {
		if (unlUsed && LEGACY_REJECT.includes(e?.code)) {
			limitContract.set('legacy');
			return send(legacyBody(body, keys, zeroUsed));
		}
		throw e;
	}
}
function legacyBody(body, keys, zeroUsed) {
	if (zeroUsed) throw new ApiError(400, 'limits_zero_unsupported');
	const b = { ...body };
	for (const k of keys) if (b[k] === UNLIMITED) b[k] = 0;
	return b;
}
