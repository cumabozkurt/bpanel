<script>
	import { ShieldCheck, Download, Undo2 } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t } from '$lib/i18n/index.js';
	import { showErr, ok, ask } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';

	let zones = $state([]);
	let zone = $state('');
	let tab = $state('dnssec');
	let sec = $state(null);
	let text = $state('');
	let mode = $state('merge');
	let pv = $state(null);
	let findings = $state([]);
	let hist = $state([]);
	let busy = $state(false);

	async function init() {
		try {
			zones = (await api.get('/user/domains')).filter((d) => d.kind !== 'sub').map((d) => d.name);
			zone = zones[0] || '';
			if (zone) load();
		} catch (e) { showErr(e); }
	}
	init();
	const base = () => '/user/dnsx/' + encodeURIComponent(zone);
	async function load() {
		pv = null;
		try {
			if (tab === 'dnssec') sec = await api.get(base() + '/dnssec');
			if (tab === 'check') findings = (await api.get(base() + '/check')).findings;
			if (tab === 'history') hist = (await api.get(base() + '/history')).items;
		} catch (e) { showErr(e); }
	}
	function pick(x) { tab = x; load(); }
	async function setSec(on) {
		if (!on && !ask('dnsx.disable_q', { zone })) return;
		busy = true;
		try { sec = await api.post(base() + '/dnssec', { enabled: on }); ok('common.saved'); } catch (e) { showErr(e); }
		busy = false;
	}
	async function exportZone() {
		try {
			const r = await api.get(base() + '/export');
			text = r.text;
			const a = document.createElement('a');
			a.href = URL.createObjectURL(new Blob([r.text], { type: 'text/plain' }));
			a.download = r.filename; a.click(); URL.revokeObjectURL(a.href);
		} catch (e) { showErr(e); }
	}
	async function preview() {
		busy = true;
		try { pv = await api.post(base() + '/import/preview', { text, mode }); } catch (e) { showErr(e); }
		busy = false;
	}
	async function apply(force) {
		busy = true;
		try { const r = await api.post(base() + '/import/apply', { text, mode, force }); ok('dnsx.applied', { n: r.applied }); pv = null; text = ''; }
		catch (e) { showErr(e); }
		busy = false;
	}
	async function revert(c) {
		if (!ask('dnsx.revert_q', { name: c.name, type: c.type })) return;
		try { await api.post(base() + '/history/' + c.id + '/revert', {}); ok('dnsx.reverted'); load(); }
		catch (e) {
			if (e?.code === 'dnsx_revert_conflict' && ask('dnsx.revert_force_q')) {
				try { await api.post(base() + '/history/' + c.id + '/revert', { force: true }); ok('dnsx.reverted'); load(); } catch (e2) { showErr(e2); }
			} else showErr(e);
		}
	}
	const recs = (s) => (s ? s.ttl + ' ' + s.records.join(' | ') : $t('dnsx.none'));
	const hasErr = (fs) => (fs || []).some((f) => f.level === 'error');
	const lvClass = { error: 'red', warn: 'amber', info: 'blue' };
</script>

<PageHead title={$t('tools.dns_tools')} desc={$t('dnsx.desc')} icon={ShieldCheck} />

<section class="card">
	<label class="field"><span>{$t('dnsx.zone')}</span>
		<select bind:value={zone} onchange={load}>{#each zones as z}<option value={z}>{z}</option>{/each}</select></label>
	<div class="tabs" role="tablist">
		{#each ['dnssec', 'import', 'check', 'history'] as x}
			<button role="tab" class="btn" class:primary={tab === x} aria-selected={tab === x} onclick={() => pick(x)}>{$t('dnsx.tab_' + x)}</button>
		{/each}
	</div>
</section>

{#if zone && tab === 'dnssec' && sec}
	<section class="card">
		{#if sec.status === 'not_installed'}
			<p class="badge amber" role="status">{$t('dnsx.dnssec_na')}: {sec.reason}</p>
		{:else}
			<p><span class="badge" class:green={sec.status === 'active'}>{$t(sec.status === 'active' ? 'dnsx.dnssec_active' : 'dnsx.dnssec_inactive')}</span></p>
			{#if sec.reason}<p class="muted">{$t('dnsx.simulated')}</p>{/if}
			{#if sec.status === 'active'}
				<h3>{$t('dnsx.ds_title')}</h3>
				<p class="muted">{$t('dnsx.ds_help')}</p>
				{#each sec.ds as d}<pre class="mono">{d}</pre>{/each}
				<button class="btn danger" disabled={busy} onclick={() => setSec(false)}>{$t('dnsx.disable')}</button>
			{:else}
				<button class="btn primary" disabled={busy} onclick={() => setSec(true)}>{$t('dnsx.enable')}</button>
			{/if}
		{/if}
	</section>
{/if}

{#if zone && tab === 'import'}
	<section class="card">
		<button class="btn" onclick={exportZone}><Download size={16} /> {$t('dnsx.export')}</button>
		<label class="field"><span>{$t('dnsx.import_text')}</span><textarea bind:value={text} rows="12" class="mono" maxlength="262144"></textarea></label>
		<p class="muted">{$t('dnsx.import_help')}</p>
		<label class="field"><span>{$t('dnsx.mode')}</span><select bind:value={mode}>
			<option value="merge">{$t('dnsx.mode_merge')}</option><option value="replace">{$t('dnsx.mode_replace')}</option></select></label>
		<button class="btn" disabled={busy || !text} onclick={preview}>{$t('dnsx.preview')}</button>
	</section>
	{#if pv}
		<section class="card">
			{#if pv.errors.length}
				<h3>{$t('dnsx.parse_errors')}</h3>
				<ul>{#each pv.errors as e}<li class="red">{$t('dnsx.line', { line: e.line })}: {$t('dnsx.p_' + e.code)} <code>{e.detail}</code></li>{/each}</ul>
			{:else}
				{#each pv.notes as n}<p class="muted">{$t('dnsx.line', { line: n.line })}: {$t('errors.' + n.code)} ({n.type})</p>{/each}
				<h3>{$t('dnsx.findings')}</h3>
				{#each pv.findings as f}<p><span class="badge {lvClass[f.level]}">{$t('dnsx.lv_' + f.level)}</span> {f.name} {f.type}: {$t('dnsx.f_' + f.code)}</p>{:else}<p>{$t('dnsx.no_findings')}</p>{/each}
				<div class="tw"><table class="table">
					<thead><tr><th>{$t('common.actions')}</th><th>Name</th><th>Type</th><th>{$t('dnsx.before')}</th><th>{$t('dnsx.after')}</th></tr></thead>
					<tbody>{#each pv.changes as c}<tr><td>{$t('dnsx.act_' + c.action)}</td><td>{c.name}</td><td>{c.type}</td><td class="mono">{recs(c.before)}</td><td class="mono">{recs(c.after)}</td></tr>
					{:else}<tr><td colspan="5" class="empty">{$t('dnsx.no_changes')}</td></tr>{/each}</tbody>
				</table></div>
				{#if pv.changes.length}
					{#if hasErr(pv.findings)}<button class="btn danger" disabled={busy} onclick={() => apply(true)}>{$t('dnsx.apply_force')}</button>
					{:else}<button class="btn primary" disabled={busy} onclick={() => apply(false)}>{$t('dnsx.apply')}</button>{/if}
				{/if}
			{/if}
		</section>
	{/if}
{/if}

{#if zone && tab === 'check'}
	<section class="card">
		{#each findings as f}<p><span class="badge {lvClass[f.level]}">{$t('dnsx.lv_' + f.level)}</span> {f.name} {f.type}: {$t('dnsx.f_' + f.code)}</p>{:else}<p>{$t('dnsx.no_findings')}</p>{/each}
	</section>
{/if}

{#if zone && tab === 'history'}
	<section class="card"><div class="tw"><table class="table">
		<thead><tr><th>{$t('dnsx.when')}</th><th>{$t('dnsx.who')}</th><th>{$t('common.actions')}</th><th>Name</th><th>{$t('dnsx.before')}</th><th>{$t('dnsx.after')}</th><th><span class="sr-only">{$t('dnsx.revert')}</span></th></tr></thead>
		<tbody>{#each hist as c}<tr>
			<td>{new Date(c.created_at * 1000).toLocaleString()}</td><td>{c.actor}</td><td>{$t('dnsx.act_' + c.action)}</td>
			<td>{c.name} {c.type}</td><td class="mono">{recs(c.before)}</td><td class="mono">{recs(c.after)}</td>
			<td><button class="linkbtn" onclick={() => revert(c)}><Undo2 size={13} /> {$t('dnsx.revert')}</button></td></tr>
		{:else}<tr><td colspan="7" class="empty">{$t('dnsx.history_empty')}</td></tr>{/each}</tbody>
	</table></div></section>
{/if}

<style>
	.tabs { display: flex; gap: 6px; flex-wrap: wrap; margin-top: 8px; }
	.mono { font-family: ui-monospace, monospace; font-size: 12px; white-space: pre-wrap; word-break: break-all; }
	.red { color: var(--red, #c00); }
</style>
