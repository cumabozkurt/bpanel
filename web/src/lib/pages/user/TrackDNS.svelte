<script>
	import { Search, Route } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t } from '$lib/i18n/index.js';
	import { showErr } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';

	// v0.4 devx: Track DNS - resolver lookups and traceroute.
	let host = $state('');
	let type = $state('A');
	let res = $state(null);
	let trace = $state(null);
	let busy = $state('');
	async function lookup(ev) {
		ev.preventDefault();
		busy = 'lookup';
		try { res = await api.get(`/user/dns-lookup?host=${encodeURIComponent(host.trim())}&type=${type}`); } catch (e) { showErr(e); }
		busy = '';
	}
	async function traceroute() {
		busy = 'trace';
		trace = null;
		try { trace = await api.post('/user/traceroute', { host: host.trim() }); } catch (e) { showErr(e); }
		busy = '';
	}
</script>

<PageHead title={$t('devx.track_title')} desc={$t('devx.track_desc')} icon={Search} />
<form class="card pad" onsubmit={lookup}>
	<div class="row gap">
		<label class="field grow"><span>{$t('devx.track_host')}</span><input bind:value={host} required maxlength="253" placeholder="example.com" /></label>
		<label class="field"><span>{$t('devx.track_type')}</span><select bind:value={type}>{#each ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'CAA'] as ty}<option>{ty}</option>{/each}</select></label>
	</div>
	<div class="row gap">
		<button class="btn primary" disabled={!!busy}><Search size={14} /> {$t('devx.track_lookup')}</button>
		<button type="button" class="btn" disabled={!!busy || !host.trim()} onclick={traceroute}><Route size={14} /> {$t('devx.track_traceroute')}</button>
	</div>
</form>
{#if res}
	<div class="card pad">
		<h2 class="h3">{res.host} · {res.type} · {$t('devx.track_status.' + res.status)}</h2>
		{#if res.records.length}<pre>{res.records.join('\n')}</pre>{:else}<p class="muted">{$t('devx.track_none')}</p>{/if}
	</div>
{/if}
{#if busy === 'trace'}<p class="muted">{$t('devx.track_running')}</p>{/if}
{#if trace}
	<div class="card pad">
		{#if trace.status === 'not_installed'}<p class="warn" role="status">{$t('devx.track_not_installed')}</p>
		{:else}<h2 class="h3">{trace.tool}</h2><pre class="small">{trace.output}</pre>{/if}
	</div>
{/if}
