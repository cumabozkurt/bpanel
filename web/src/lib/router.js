import { writable } from 'svelte/store';
import { goto } from '$app/navigation';

// Current path, kept in sync with SvelteKit navigation by App.svelte.
export const path = writable(typeof location !== 'undefined' ? location.pathname : '/');

/** match('/dns/:domain', '/dns/a.com') -> {domain: 'a.com'} | null */
export function match(pattern, p) {
	const a = pattern.split('/').filter(Boolean);
	const b = p.split('/').filter(Boolean);
	if (a.length !== b.length) return null;
	const params = {};
	for (let i = 0; i < a.length; i++) {
		if (a[i].startsWith(':')) params[a[i].slice(1)] = decodeURIComponent(b[i]);
		else if (a[i] !== b[i]) return null;
	}
	return params;
}

export function nav(to) {
	goto(to);
}
