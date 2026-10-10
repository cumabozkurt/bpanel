<script>
	import { ShieldCheck, Download, RotateCcw, Trash2, BadgeCheck, ScanSearch } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t } from '$lib/i18n/index.js';
	import { session } from '$lib/stores.js';
	import { showErr, ok, ask } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';
	import ShieldPolicies from './ShieldPolicies.svelte';

	let me = $derived($session?.user);
	let isAdmin = $derived(me?.role === 'admin');
	let st = $state(null);
	let stErr = $state('');
	let dets = $state([]);
	let total = $state(0);
	let offset = $state(0);
	const limit = 50;
	let quar = $state([]);
	let accounts = $state([]);
	let scanAcct = $state('');
	let scanPath = $state('');
	let scanRes = $state(null);
	let busy = $state(false);
	let tab = $state('overview');

	async function loadStatus() {
		try { st = await api.get('/admin/shield/status'); stErr = ''; } catch (e) { st = null; stErr = e.code || 'agent_unreachable'; }
	}
	async function loadDets() {
		try {
			const r = await api.get(`/admin/shield/detections?limit=${limit}&offset=${offset}`);
			dets = r.items; total = r.total;
		} catch (e) { showErr(e); }
	}
	async function loadQuar() {
		try { quar = (await api.get('/admin/shield/quarantine')).items; } catch (e) { quar = []; showErr(e); }
	}
	async function load() {
		await Promise.all([loadStatus(), loadDets(), loadQuar()]);
		try { accounts = ((await api.get('/admin/accounts?limit=500')).items ?? []).filter((a) => a.role === 'user'); } catch { accounts = []; }
	}
	load();

	function page(d) { offset = Math.max(0, offset + d * limit); loadDets(); }
	async function qact(item, kind) {
		const id = item.item.id;
		try {
			if (kind === 'restore') { if (!ask('shield.confirm_restore', { path: item.item.orig_path })) return; await api.post(`/admin/shield/quarantine/${id}/restore`); ok('shield.restored'); }
			if (kind === 'delete') { if (!ask('shield.confirm_delete', { path: item.item.orig_path })) return; await api.del(`/admin/shield/quarantine/${id}`); ok('shield.deleted'); }
			if (kind === 'fp' || kind === 'fpg') { await api.post(`/admin/shield/quarantine/${id}/false-positive`, { scope: kind === 'fpg' ? 'global' : 'account' }); ok('shield.marked_fp'); }
		} catch (e) { showErr(e); }
		loadQuar(); loadDets(); loadStatus();
	}
	async function scan(e) {
		e.preventDefault();
		busy = true; scanRes = null;
		try { scanRes = await api.post('/admin/shield/scan', { account_id: Number(scanAcct), path: scanPath }); loadDets(); loadQuar(); } catch (err) { showErr(err); }
		busy = false;
	}
	const when = (ts) => (ts ? new Date(ts * 1000).toLocaleString() : '—');
	const engStatus = (s) => $t('shield.st.' + s) === 'shield.st.' + s ? s : $t('shield.st.' + s);
</script>

<PageHead title={$t('shield.title')} desc={$t('shield.desc')} icon={ShieldCheck} />
<div class="card pad warn" role="note">{$t('shield.banner')}</div>

<div class="tabs" role="tablist">
	{#each ['overview', 'policies'] as k}
		<button role="tab" class="btn ghost sm" class:active={tab === k} aria-selected={tab === k} onclick={() => (tab = k)}>{$t('shield.tab.' + k)}</button>
	{/each}
</div>

{#if tab === 'policies'}
<ShieldPolicies {accounts} />
{:else}

<h2>{$t('shield.engines')}</h2>
{#if stErr}<div class="card pad warn" role="status">{$t('shield.status_unavailable', { code: stErr })}</div>{/if}
{#if st}
	<div class="card tw">
		<table class="table">
			<thead><tr><th>{$t('shield.engine')}</th><th>{$t('shield.kind')}</th><th>{$t('shield.status')}</th><th>{$t('shield.version')}</th><th>{$t('shield.db_age')}</th><th>{$t('shield.upload')}</th><th>{$t('shield.on_demand')}</th></tr></thead>
			<tbody>
				{#each st.status.engines ?? [] as e (e.name)}
					<tr><td><b>{e.name}</b><div class="small muted">{e.license}</div></td><td>{e.kind}</td>
						<td><span class="badge {e.status === 'ok' ? 'ok' : 'warn'}">{engStatus(e.status)}</span>{#if e.reason}<div class="small muted">{e.reason}</div>{/if}</td>
						<td>{e.version || '—'}{#if e.signature_version}<div class="small muted">{e.signature_version}</div>{/if}</td>
						<td>{e.db_age_hours ? $t('shield.hours', { n: e.db_age_hours }) : '—'}</td>
						<td>{e.realtime ? '✓' : '—'}</td><td>{e.on_demand ? '✓' : '—'}</td></tr>
				{/each}
			</tbody>
		</table>
	</div>
	<h3>{$t('shield.coverage')}</h3>
	<div class="card tw">
		<table class="table">
			<thead><tr><th>{$t('shield.layer')}</th><th>{$t('shield.status')}</th><th>{$t('shield.detail')}</th></tr></thead>
			<tbody>
				<tr><td>{$t('shield.layer_upload')}</td><td><span class="badge ok">{$t('shield.st.ok')}</span></td><td>{$t('shield.layer_upload_d')}</td></tr>
				<tr><td>{$t('shield.layer_realtime')}</td><td><span class="badge {st.status.realtime === 'on' ? 'ok' : 'warn'}">{$t('shield.rt.' + st.status.realtime)}</span></td>
					<td>{st.status.reason || ''}{#if st.status.coverage} · {$t('shield.watches', { n: st.status.coverage.watches, max: st.status.coverage.max_user_watches })}{/if}</td></tr>
				<tr><td>{$t('shield.layer_fanotify')}</td><td><span class="badge {st.status.fanotify ? 'ok' : 'warn'}">{st.status.fanotify ? $t('shield.available') : $t('shield.st.unavailable')}</span></td><td>{st.status.fanotify_reason || ''}</td></tr>
				<tr><td>{$t('shield.queue')}</td><td>{st.status.queue ? st.status.queue.pending : '—'}</td><td>{#if st.status.queue}{$t('shield.queue_d', { f: st.status.queue.in_flight, d: st.status.queue.dropped })}{/if}</td></tr>
				<tr><td>{$t('shield.quarantine')}</td><td>{st.status.quarantine_items}</td><td>{$t('shield.restore_requests', { n: st.restore_requests })}</td></tr>
			</tbody>
		</table>
	</div>
{/if}

<h2>{$t('shield.scan_now')}</h2>
<form class="card pad" onsubmit={scan}>
	<div class="grid3">
		<label class="field"><span>{$t('shield.account')}</span><select bind:value={scanAcct} required><option value="">—</option>{#each accounts as a (a.id)}<option value={String(a.id)}>{a.username}</option>{/each}</select></label>
		<label class="field"><span>{$t('shield.path')}</span><input bind:value={scanPath} required maxlength="4096" placeholder="public_html/index.php" /></label>
	</div>
	<button class="btn primary" disabled={busy}><ScanSearch size={15} /> {$t('shield.scan')}</button>
	{#if scanRes}<p class="small">{$t('shield.outcome.' + scanRes.result.outcome)}{#if scanRes.quarantine_id} · {$t('shield.quarantined')}{/if}</p>{/if}
</form>

<h2>{$t('shield.quarantine')}</h2>
<div class="card tw">
	<table class="table">
		<thead><tr><th>{$t('shield.account')}</th><th>{$t('shield.path')}</th><th>{$t('shield.signature')}</th><th>{$t('shield.time')}</th><th></th></tr></thead>
		<tbody>
			{#each quar as q (q.item.id)}
				<tr><td>{q.item.account}</td><td class="mono small">{q.item.orig_path}{#if q.restore_requested_at}<div><span class="badge warn">{$t('shield.restore_requested')}</span></div>{/if}</td>
					<td>{(q.item.detections ?? []).map((d) => d.signature).join(', ') || '—'}</td><td>{when(Date.parse(q.item.ts) / 1000)}</td>
					<td class="right nowrap">
						<button class="btn ghost sm" title={$t('shield.restore')} aria-label={$t('shield.restore')} onclick={() => qact(q, 'restore')}><RotateCcw size={14} /></button>
						<button class="btn ghost sm" title={$t('shield.false_positive')} aria-label={$t('shield.false_positive')} onclick={() => qact(q, 'fp')}><BadgeCheck size={14} /></button>
						{#if isAdmin}<button class="btn ghost sm" onclick={() => qact(q, 'fpg')}>{$t('shield.fp_global')}</button>{/if}
						<button class="btn ghost sm" title={$t('common.delete')} aria-label={$t('common.delete')} onclick={() => qact(q, 'delete')}><Trash2 size={14} /></button>
					</td></tr>
			{:else}<tr><td colspan="5" class="empty">{$t('shield.no_quarantine')}</td></tr>{/each}
		</tbody>
	</table>
</div>

<h2>{$t('shield.detections')}</h2>
<div class="row"><a class="btn sm" href="/api/v1/admin/shield/detections?format=csv" download><Download size={14} /> CSV</a><a class="btn sm" href={`/api/v1/admin/shield/detections?limit=500&format=json`} target="_blank" rel="noopener">JSON</a></div>
<div class="card tw">
	<table class="table">
		<thead><tr><th>{$t('shield.time')}</th><th>{$t('shield.account')}</th><th>{$t('shield.source')}</th><th>{$t('shield.path')}</th><th>{$t('shield.result')}</th><th>{$t('shield.signature')}</th><th>{$t('shield.action')}</th></tr></thead>
		<tbody>
			{#each dets as d (d.id)}
				<tr><td class="nowrap">{when(d.ts)}</td><td>{d.account}</td><td>{$t('shield.src.' + d.source)}</td><td class="mono small">{d.path}</td>
					<td><span class="badge {d.outcome === 'infected' ? 'err' : 'warn'}">{$t('shield.outcome.' + d.outcome)}</span></td>
					<td>{d.signature || '—'}{#if d.engine}<div class="small muted">{d.engine}</div>{/if}</td><td>{d.action}</td></tr>
			{:else}<tr><td colspan="7" class="empty">{$t('shield.no_detections')}</td></tr>{/each}
		</tbody>
	</table>
</div>
{#if total > limit}
	<div class="row"><button class="btn sm" disabled={offset === 0} onclick={() => page(-1)}>‹</button><span class="small muted">{offset + 1}–{Math.min(offset + limit, total)} / {total}</span><button class="btn sm" disabled={offset + limit >= total} onclick={() => page(1)}>›</button></div>
{/if}
{/if}
