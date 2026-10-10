<script>
	import { RefreshCw, KeyRound, Trash2 } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t } from '$lib/i18n/index.js';
	import { showErr, ok, ask } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';

	// v0.4 devx: Dynamic DNS for subdomains (token shown once, stored hashed).
	let data = $state(null);
	let shown = $state(null);
	async function load() {
		try { data = await api.get('/user/ddns'); } catch (e) { showErr(e); }
	}
	async function enable(h) {
		if (h.enabled && !ask('devx.ddns_rotate_confirm', { domain: h.domain })) return;
		try {
			const r = await api.post('/user/ddns', { domain_id: h.domain_id });
			shown = { domain: r.domain, url: location.origin + r.update_path };
			load();
		} catch (e) { showErr(e); }
	}
	async function disable(h) {
		if (!ask('devx.ddns_disable_confirm', { domain: h.domain })) return;
		try { await api.del(`/user/ddns/${h.id}`); ok('devx.ddns_disabled'); load(); } catch (e) { showErr(e); }
	}
	const when = (u) => (u ? new Date(u * 1000).toLocaleString() : '—');
	load();
</script>

<PageHead title={$t('devx.ddns_title')} desc={$t('devx.ddns_desc')} icon={RefreshCw} />
{#if shown}
	<div class="card pad" role="status">
		<p><strong>{shown.domain}</strong> — {$t('devx.ddns_once')}</p>
		<pre class="small">{shown.url}</pre>
		<p class="small muted">{$t('devx.ddns_usage')}</p>
	</div>
{/if}
{#if data}
	<div class="card tw">
		<table class="table">
			<thead><tr><th>{$t('acc.domain')}</th><th>IPv4</th><th>IPv6</th><th>{$t('devx.ddns_last')}</th><th></th></tr></thead>
			<tbody>
				{#each data.hosts as h (h.domain_id)}
					<tr><td>{h.domain}</td><td>{h.last_ipv4 || '—'}</td><td>{h.last_ipv6 || '—'}</td><td>{when(h.last_update)}</td>
						<td class="right">
							<button class="btn sm" onclick={() => enable(h)}><KeyRound size={14} /> {h.enabled ? $t('devx.ddns_rotate') : $t('devx.ddns_enable')}</button>
							{#if h.enabled}<button class="btn ghost sm" aria-label={$t('common.delete')} onclick={() => disable(h)}><Trash2 size={14} /></button>{/if}
						</td></tr>
				{:else}<tr><td colspan="5" class="empty">{$t('devx.ddns_empty')}</td></tr>{/each}
			</tbody>
		</table>
	</div>
{/if}
