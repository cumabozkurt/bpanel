<script>
	// v1.1: visitor statistics (Awstats/Visitors style) from the domain's access log.
	import { BarChart3 } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t } from '$lib/i18n/index.js';
	import { showErr } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';
	let domains = $state([]);
	let domain = $state('');
	let st = $state(null);
	let busy = $state(false);
	async function load() {
		try {
			domains = (await api.get('/user/stats/visitors')).domains ?? [];
			if (!domain && domains.length) { domain = domains[0]; show(); }
		} catch (e) { showErr(e); }
	}
	async function show() {
		if (!domain) return;
		busy = true;
		try { st = (await api.get('/user/stats/visitors?domain=' + encodeURIComponent(domain))).stats; } catch (e) { showErr(e); }
		busy = false;
	}
	const max = (rows) => Math.max(1, ...(rows ?? []).map((r) => r.n ?? 0));
	const tot = (k) => (st?.days ?? []).reduce((a, d) => a + (d[k] ?? 0), 0);
	const fmtB = (n) => (n > 1 << 30 ? (n / (1 << 30)).toFixed(1) + ' GB' : n > 1 << 20 ? (n / (1 << 20)).toFixed(1) + ' MB' : Math.round((n ?? 0) / 1024) + ' KB');
	load();
</script>

<PageHead title={$t('tools.visitors')} desc={$t('v11.visitors_desc')} icon={BarChart3} />
<div class="stack">
	<div class="card"><div class="card-body row wraprow">
		<label class="field" style="max-width:360px"><span>{$t('webx.domain')}</span>
			<select bind:value={domain} onchange={show} disabled={!domains.length}>{#each domains as d}<option value={d}>{d}</option>{/each}</select></label>
		<button class="btn" onclick={show} disabled={busy || !domain}>{$t('v11.refresh')}</button>
	</div></div>
	{#if st}
		{#if st.status !== 'ok'}<p class="empty">{$t('v11.no_log')}</p>{/if}
		<div class="card"><div class="card-body kv small">
			<div>{$t('v11.hits')}</div><div>{tot('hits')}</div>
			<div>{$t('v11.pages')}</div><div>{tot('pages')}</div>
			<div>{$t('v11.unique_visitors')}</div><div>{tot('visitors')}</div>
			<div>{$t('v11.bandwidth')}</div><div>{fmtB(tot('bytes'))}</div>
			{#if st.truncated}<div></div><div class="muted">{$t('v11.truncated')}</div>{/if}
		</div></div>
		{#if st.days?.length}
			<div class="card tw"><div class="card-head"><h2>{$t('v11.by_day')}</h2></div>
				<table class="table"><thead><tr><th>{$t('v11.day')}</th><th>{$t('v11.hits')}</th><th>{$t('v11.pages')}</th><th>{$t('v11.unique_visitors')}</th><th>{$t('v11.bandwidth')}</th></tr></thead>
					<tbody>{#each st.days as d}<tr><td>{d.day}</td><td>{d.hits}</td><td>{d.pages}</td><td>{d.visitors}</td><td>{fmtB(d.bytes)}</td></tr>{/each}</tbody></table></div>
		{/if}
		{#each [['pages', 'v11.top_pages'], ['referrers', 'v11.top_referrers'], ['browsers', 'v11.browsers'], ['systems', 'v11.systems'], ['codes', 'v11.status_codes'], ['hosts', 'v11.top_hosts']] as [k, label]}
			{#if st[k]?.length}
				<div class="card tw">
					<div class="card-head"><h2>{$t(label)}</h2></div>
					<table class="table"><tbody>
						{#each st[k] as r}
							<tr><td class="mono small">{r.key}</td><td style="width:45%"><div class="bar" style="width:{Math.round((r.n / max(st[k])) * 100)}%"></div></td><td class="right">{r.n}</td></tr>
						{/each}
					</tbody></table>
				</div>
			{/if}
		{/each}
		{#if st.recent?.length}
			<div class="card tw"><div class="card-head"><h2>{$t('v11.recent')}</h2></div>
				<table class="table small"><tbody>{#each st.recent as h}<tr><td>{new Date(h.time * 1000).toLocaleString()}</td><td class="mono">{h.ip}</td><td class="mono">{h.method} {h.path}</td><td>{h.status}</td></tr>{/each}</tbody></table></div>
		{/if}
		{#if !tot('hits')}<p class="empty">{$t('v11.no_traffic')}</p>{/if}
	{/if}
</div>

<style>
	.wraprow { flex-wrap: wrap; align-items: flex-end; gap: 12px; }
	.bar { height: 8px; border-radius: 4px; background: var(--accent, #3b82f6); min-width: 2px; }
</style>
