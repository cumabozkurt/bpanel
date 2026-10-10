<script>
	// v0.4 obsx: OS health, file integrity monitoring, monitoring settings and
	// log retention, Prometheus scrape information.
	import { Activity } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t } from '$lib/i18n/index.js';
	import { showErr, ok, ask } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';
	let health = $state(null);
	let loading = $state(false);
	let fim = $state(null);
	let fimRes = $state(null);
	let cfg = $state(null);
	const when = (ts) => (ts ? new Date(ts * 1000).toLocaleString() : '—');
	const gb = (b) => (b / 1073741824).toFixed(1) + ' GB';
	async function loadHealth() { loading = true; try { health = await api.get('/admin/obsx/health'); } catch (e) { showErr(e); } loading = false; }
	async function loadFim() { try { fim = await api.get('/admin/obsx/fim'); } catch (e) { showErr(e); } }
	async function baseline() { if (!ask('obsx.baseline_confirm')) return; try { const r = await api.post('/admin/obsx/fim/baseline'); ok('obsx.baseline_done', { n: r.files }); loadFim(); } catch (e) { showErr(e); } }
	async function check() { try { fimRes = await api.post('/admin/obsx/fim/check'); loadFim(); } catch (e) { showErr(e); } }
	async function loadCfg() { try { cfg = await api.get('/admin/obsx/settings'); } catch (e) { showErr(e); } }
	async function saveCfg(e) {
		e.preventDefault();
		try {
			cfg = await api.put('/admin/obsx/settings', {
				metrics_localhost: cfg.metrics_localhost, eval_interval_min: Number(cfg.eval_interval_min), fim_interval_min: Number(cfg.fim_interval_min), mail_from: cfg.mail_from,
				audit_days: Number(cfg.retention.audit_days), events_days: Number(cfg.retention.events_days), bandwidth_days: Number(cfg.retention.bandwidth_days), incidents_days: Number(cfg.retention.incidents_days)
			});
			ok('obsx.saved');
		} catch (err) { showErr(err); }
	}
	loadHealth();
	loadFim();
	loadCfg();
	const cls = (s) => (s === 'ok' ? 'green' : s === 'failed' ? 'red' : 'amber');
</script>

<PageHead title={$t('tools.monitoring')} desc={$t('obsx.mon_desc')} icon={Activity} />
<div class="card">
	<h3>{$t('obsx.os_health')}</h3>
	<button class="btn" onclick={loadHealth} disabled={loading}>{$t('obsx.refresh')}</button>
	{#if health}
		<table class="table">
			<tbody>
				{#each health.checks as c}
					<tr><td>{$t('obsx.c_' + c.id)}</td><td><span class="badge {cls(c.status)}">{$t('obsx.hs_' + c.status)}</span></td><td class="small">{c.reason ?? ''}{#if c.details?.length}<div class="mono">{c.details.join(' · ')}</div>{/if}</td></tr>
				{/each}
			</tbody>
		</table>
		<h4>{$t('obsx.disks')}</h4>
		<table class="table">
			<thead><tr><th>{$t('obsx.mount')}</th><th>{$t('obsx.used')}</th><th>{$t('obsx.inodes')}</th></tr></thead>
			<tbody>{#each health.disks ?? [] as d}<tr><td class="mono">{d.mount}</td><td>{d.used_pct.toFixed(1)}% ({gb(d.used)} / {gb(d.total)})</td><td>{d.inode_pct.toFixed(1)}%</td></tr>{/each}</tbody>
		</table>
		{#if health.reason}<p class="muted small">{health.reason}</p>{/if}
	{/if}
</div>

<div class="card">
	<h3>{$t('obsx.fim')}</h3>
	<p class="muted small">{$t('obsx.fim_desc')}</p>
	{#if fim}
		<div class="kv small">
			<div>{$t('obsx.baseline_files')}</div><div>{fim.baseline_files}</div>
			<div>{$t('obsx.baseline_at')}</div><div>{when(fim.baseline_at)}</div>
			<div>{$t('obsx.last_check')}</div><div>{fim.last ? when(fim.last.at) + ' — ' + $t('obsx.n_changes', { n: fim.last.changes.length }) : '—'}</div>
		</div>
	{/if}
	<div class="row">
		<button class="btn" onclick={baseline}>{$t('obsx.new_baseline')}</button>
		<button class="btn primary" onclick={check} disabled={!fim?.baseline_files}>{$t('obsx.check_now')}</button>
	</div>
	{#if (fimRes?.changes ?? fim?.last?.changes)?.length}
		<table class="table"><tbody>{#each fimRes?.changes ?? fim.last.changes as c}<tr><td>{$t('obsx.ch_' + c.change)}</td><td class="mono">{c.path}</td><td class="small">{(c.fields ?? []).join(', ')}</td></tr>{/each}</tbody></table>
	{/if}
</div>

{#if cfg}
	<form class="card" onsubmit={saveCfg}>
		<h3>{$t('obsx.settings')}</h3>
		<label><input type="checkbox" bind:checked={cfg.metrics_localhost} /> {$t('obsx.metrics_localhost')}</label>
		<p class="muted small">{$t('obsx.metrics_note')}</p>
		<label>{$t('obsx.eval_interval')} <input type="number" min="0" max="1440" bind:value={cfg.eval_interval_min} /></label>
		<label>{$t('obsx.fim_interval')} <input type="number" min="0" max="10080" bind:value={cfg.fim_interval_min} /></label>
		<label>{$t('obsx.mail_from')} <input type="email" bind:value={cfg.mail_from} /></label>
		<h4>{$t('obsx.retention')}</h4>
		{#each ['audit_days', 'events_days', 'bandwidth_days', 'incidents_days'] as k}
			<label>{$t('obsx.ret_' + k)} <input type="number" min={cfg.retention_limits[k][0]} max={cfg.retention_limits[k][1]} bind:value={cfg.retention[k]} /></label>
		{/each}
		<button class="btn primary" type="submit">{$t('obsx.save')}</button>
	</form>
{/if}

<style>
	.row { display: flex; gap: 8px; flex-wrap: wrap; margin: 8px 0; }
	label { display: block; margin: 6px 0; }
</style>
