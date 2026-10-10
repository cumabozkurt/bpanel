<script>
	import { Activity } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t } from '$lib/i18n/index.js';
	import { showErr } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';

	// v0.4 usagex: monthly bandwidth per domain from the nginx domain logs (user + admin realm).
	let { admin = false } = $props();
	let month = $state(new Date().toISOString().slice(0, 7));
	let data = $state(null);
	let busy = $state(false);
	const fmt = (b) => { const u = ['B', 'KB', 'MB', 'GB', 'TB']; let i = 0; let n = b; while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; } return (i ? n.toFixed(1) : n) + ' ' + u[i]; };
	const max = $derived(Math.max(1, ...(data?.days ?? []).map((d) => d.bytes)));

	async function load() {
		try { data = await api.get((admin ? '/admin/bandwidth' : '/user/bandwidth') + '?month=' + month); } catch (e) { showErr(e); }
	}
	async function collect() {
		busy = true;
		try { await api.post('/admin/bandwidth/collect', {}); await load(); } catch (e) { showErr(e); }
		busy = false;
	}
	load();
</script>

<PageHead title={$t('usagex.bw_title')} desc={$t('usagex.bw_desc')} icon={Activity}>
	{#snippet actions()}{#if admin}<button class="btn" disabled={busy} onclick={collect}>{$t('usagex.bw_collect')}</button>{/if}{/snippet}
</PageHead>
<div class="card pad row">
	<label class="field"><span>{$t('usagex.bw_month')}</span><input type="month" bind:value={month} onchange={load} /></label>
	{#if data}<div><strong>{fmt(data.total_bytes)}</strong> · {$t('usagex.bw_hits', { n: data.total_hits })}{#if data.limit_mb} · {$t('usagex.bw_limit', { mb: data.limit_mb })}{/if}</div>{/if}
</div>
{#if data}
	{#if data.days.length}
		<div class="card pad" role="img" aria-label={$t('usagex.bw_chart')}>
			<div style="display:flex;align-items:flex-end;gap:2px;height:120px">
				{#each data.days as d}<div title="{d.day}: {fmt(d.bytes)}" style="flex:1;background:var(--accent,#3b82f6);height:{Math.max(2, (d.bytes / max) * 100)}%"></div>{/each}
			</div>
		</div>
	{/if}
	<div class="card tw">
		<table class="table">
			<thead><tr><th>{$t('acc.domain')}</th>{#if admin}<th>{$t('acc.username')}</th>{/if}<th class="right">{$t('usagex.bw_bytes')}</th><th class="right">{$t('usagex.bw_requests')}</th></tr></thead>
			<tbody>
				{#each data.domains as d}<tr><td>{d.domain}</td>{#if admin}<td>{d.user}</td>{/if}<td class="right">{fmt(d.bytes)}</td><td class="right">{d.hits}</td></tr>
				{:else}<tr><td colspan={admin ? 4 : 3} class="empty">{$t('usagex.bw_empty')}</td></tr>{/each}
			</tbody>
		</table>
	</div>
	<p class="small muted">{$t('usagex.bw_help')}</p>
{/if}
