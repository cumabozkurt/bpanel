// Small fetch wrapper: JSON in/out, CSRF header, typed errors.
let csrf = '';
export function setCSRF(token) { csrf = token || ''; }

export class ApiError extends Error {
	constructor(status, code, message, data) {
		super(message || code);
		this.status = status;
		this.code = code;
		this.data = data || null; // full error body (e.g. step for /user/db-wizard)
	}
}

async function request(method, path, body, opts = {}) {
	const headers = {};
	if (body !== undefined && !(body instanceof FormData)) headers['Content-Type'] = 'application/json';
	if (method !== 'GET' && csrf) headers['X-CSRF-Token'] = csrf;
	let res;
	try {
		res = await fetch('/api/v1' + path, {
			method,
			headers,
			credentials: 'same-origin',
			body: body === undefined ? undefined : body instanceof FormData ? body : JSON.stringify(body)
		});
	} catch {
		throw new ApiError(0, 'network_error');
	}
	let data = null;
	const ct = res.headers.get('content-type') || '';
	if (ct.includes('application/json')) { try { data = await res.json(); } catch { data = null; } }
	if (!res.ok) {
		if (res.status === 401 && !opts.noRedirect && typeof window !== 'undefined' && !location.pathname.startsWith('/login')) {
			window.dispatchEvent(new CustomEvent('bp:unauthenticated'));
		}
		throw new ApiError(res.status, data?.error ?? 'http_' + res.status, data?.message, data);
	}
	if (opts.withTotal) {
		const h = res.headers.get('X-Total-Count');
		return { data, total: h === null ? null : Number(h) };
	}
	return data;
}

export const api = {
	get: (p, o) => request('GET', p, undefined, o),
	/** GET a list with ?limit=&offset=; total is X-Total-Count (null when the server does not page). */
	page: (p, o) => request('GET', p, undefined, { ...o, withTotal: true }),
	post: (p, b = {}, o) => request('POST', p, b, o),
	put: (p, b = {}, o) => request('PUT', p, b, o),
	del: (p, o) => request('DELETE', p, undefined, o)
};
