<script>
	import { PieChart, Folder, Database } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t, fmt } from '$lib/i18n/index.js';
	import { showErr } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';
	let d = $state(null);
	api.get('/user/disk').then((r) => (d = r)).catch(showErr);
	let dbTotal = $derived(Object.values(d?.databases ?? {}).reduce((a, b) => a + b, 0));
	let max = $derived(Math.max(1, ...(d?.usage?.entries ?? []).map((e) => e.bytes)));
</script>

<PageHead title={$t('tools.disk_usage')} desc={$t('disk.desc')} icon={PieChart} />
{#if d}
	<div class="grid3" style="margin-bottom:16px">
		<div class="card card-body"><div class="muted small">{$t('disk.home_total')}</div><div class="big">{$fmt.bytes(d.usage.total_bytes)}</div>
			{#if d.quota_bytes}<div class="progress" style="margin-top:8px" role="progressbar" aria-label={$t('disk.home_total')} aria-valuemin="0" aria-valuemax="100" aria-valuenow={Math.round(Math.min(100, (d.usage.total_bytes / d.quota_bytes) * 100))}><div style="width:{Math.min(100, (d.usage.total_bytes / d.quota_bytes) * 100)}%"></div></div><div class="muted small">{$t('disk.of_quota', { q: $fmt.bytes(d.quota_bytes) })}</div>{/if}</div>
		<div class="card card-body"><div class="muted small">{$t('stats.db_disk')}</div><div class="big">{$fmt.bytes(dbTotal)}</div></div>
		<div class="card card-body"><div class="muted small">{$t('stats.inodes')}</div><div class="big">{$fmt.num(d.usage.inodes)}</div></div>
	</div>
	<div class="card">
		<div class="tw"><table class="table">
			<thead><tr><th>{$t('disk.location')}</th><th style="width:45%"><span class="sr-only">{$t('disk.share')}</span></th><th style="text-align:right">{$t('disk.size')}</th></tr></thead>
			<tbody>
				{#each d.usage.entries as e}
					<tr><td><a href={'/files?path=' + encodeURIComponent(e.path)}><Folder size={14} /> ~/{e.path}</a></td>
						<td><div class="progress"><div style="width:{Math.max(1, (e.bytes / max) * 100)}%"></div></div></td>
						<td style="text-align:right">{$fmt.bytes(e.bytes)}</td></tr>
				{/each}
				{#each Object.entries(d.databases ?? {}) as [n, b]}
					<tr><td><Database size={14} /> {n}</td><td><div class="progress"><div style="width:{Math.max(1, (b / max) * 100)}%"></div></div></td><td style="text-align:right">{$fmt.bytes(b)}</td></tr>
				{/each}
			</tbody>
		</table></div>
	</div>
{/if}

<style>.big { font-size: 24px; font-weight: 300; }</style>
