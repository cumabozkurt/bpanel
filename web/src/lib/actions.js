import { api } from './api.js';
import { showErr } from './util.js';
import { goto } from '$app/navigation';

/** Open a tool: navigate, open a link, or run an action. */
export async function openTool(tool) {
	if (tool.soon) return goto('/tool/' + tool.id);
	if (tool.href) return window.open(tool.href, '_blank', 'noopener');
	if (tool.to) return goto(tool.to);
	try {
		if (tool.action === 'webmail') {
			const r = await api.get('/user/webmail');
			window.open(r.url, '_blank', 'noopener');
		} else if (tool.action === 'phpmyadmin') {
			const r = await api.post('/user/phpmyadmin');
			window.open(r.url, '_blank', 'noopener');
		}
	} catch (e) {
		showErr(e);
	}
}
