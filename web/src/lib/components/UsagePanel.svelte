<script>
	// Resource usage of one account (admin: /admin/accounts/{id}/usage, user: /user/usage).
	import { api } from '$lib/api.js';
	import { t, fmt } from '$lib/i18n/index.js';
	import { showErr } from '$lib/util.js';
	import UsageChart from './UsageChart.svelte';
	let { src } = $props();
	let range = $state('24h');
	let data = $state(null);
	let busy = $state(false);
	async function load() {
		busy = true;
		try { data = await api.get(src + '?range=' + range); } catch (e) { showErr(e); }
		busy = false;
	}
	$effect(() => { src; range; load(); });
	const pts = (k) => (data?.points ?? []).map((p) => ({ ts: p.ts, v: k(p) }));
	const pct = (v) => v.toFixed(1) + '%';
	const num = (v) => String(Math.round(v));
	let lim = $derived(data?.limits ?? {});
	let evs = $derived(Object.entries(data?.events ?? {}));
</script>

{#if data?.sampler?.status === 'unsupported'}
	<div class="banner warn" role="status">{$t('iso.unsupported', { reason: data.sampler.reason || '' })}</div>
{/if}
<div class="row gap">
	<label class="small">{$t('iso.range')}
		<select bind:value={range} disabled={busy}>
			{#each ['1h', '24h', '7d', '30d'] as r}<option value={r}>{$t('iso.ranges.' + r)}</option>{/each}
		</select>
	</label>
	{#if evs.length}<span class="badge amber">{$t('iso.limit_hits')}: {evs.map(([k, v]) => $t('iso.ev.' + k) + ' ×' + v).join(', ')}</span>{/if}
</div>
{#if data && !data.points.length}<p class="muted">{$t('iso.no_data')}</p>{/if}
<div class="ugrid">
	<UsageChart label={$t('iso.cpu')} points={pts((p) => p.cpu_pct)} format={pct} max={lim.cpu_percent || null} />
	<UsageChart label={$t('iso.memory')} points={pts((p) => p.mem_bytes)} format={(v) => $fmt.bytes(v)} max={lim.mem_max_mb ? lim.mem_max_mb * 1048576 : null} />
	<UsageChart label={$t('iso.io')} points={pts((p) => p.io_r_bps + p.io_w_bps)} format={(v) => $fmt.bytes(v) + '/s'} />
	<UsageChart label={$t('iso.pids')} points={pts((p) => p.pids)} format={num} max={lim.tasks_max || null} />
</div>
<p class="small muted">{$t('iso.cpu_note')}</p>

<style>
	.ugrid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 0.75rem; margin: 0.75rem 0; }
	.row { display: flex; align-items: center; flex-wrap: wrap; gap: 0.75rem; }
	.banner { padding: 0.6rem 0.8rem; border-radius: 8px; margin-bottom: 0.75rem; background: var(--amber-bg, #fff4d6); }
</style>
