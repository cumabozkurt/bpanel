<script>
	import { Activity } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t, fmt } from '$lib/i18n/index.js';
	import { showErr } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';
	let rows = $state([]);
	let total = $state(0);
	let type = $state('');
	let severity = $state('');
	let offset = $state(0);
	const limit = 50;
	async function load() {
		const q = new URLSearchParams({ limit, offset });
		if (type) q.set('type', type);
		if (severity) q.set('severity', severity);
		try { const r = await api.get('/admin/events?' + q); rows = r.events; total = r.total; } catch (e) { showErr(e); }
	}
	load();
	function apply(e) { e.preventDefault(); offset = 0; load(); }
	function go(d) { offset = Math.max(0, offset + d); load(); }
</script>

<PageHead title={$t('tools.sec_events')} desc={$t('sec.ev_desc')} icon={Activity} />
<div class="card">
	<form class="toolbar" onsubmit={apply}>
		<input bind:value={type} placeholder="shield.*" aria-label={$t('sec.ev_type')} />
		<select bind:value={severity} aria-label={$t('sec.ev_severity')}>
			<option value="">{$t('sec.ev_all')}</option>
			<option value="info">{$t('sec.sev_info')}</option><option value="warning">{$t('sec.sev_warning')}</option><option value="critical">{$t('sec.sev_critical')}</option>
		</select>
		<button class="btn" type="submit">{$t('sec.ev_filter')}</button>
	</form>
	<div class="tw"><table class="table">
		<thead><tr><th>{$t('sec.time')}</th><th>{$t('sec.ev_type')}</th><th>{$t('sec.ev_severity')}</th><th>{$t('sec.ev_account')}</th><th>{$t('sec.ev_data')}</th></tr></thead>
		<tbody>
			{#each rows as e}
				<tr><td class="small">{$fmt.date(e.at)}</td><td class="mono small">{e.type}</td>
					<td><span class="badge" class:red={e.severity === 'critical'} class:amber={e.severity === 'warning'}>{$t('sec.sev_' + e.severity)}</span></td>
					<td>{e.account_id || '—'}</td><td class="mono small">{JSON.stringify(e.data)}</td></tr>
			{:else}<tr><td colspan="5" class="empty">{$t('common.none')}</td></tr>{/each}
		</tbody>
	</table></div>
	<div class="toolbar"><button class="btn small" disabled={offset === 0} onclick={() => go(-limit)}>‹</button> <span class="small muted">{offset + 1}–{Math.min(offset + limit, total)} / {total}</span> <button class="btn small" disabled={offset + limit >= total} onclick={() => go(limit)}>›</button></div>
</div>
