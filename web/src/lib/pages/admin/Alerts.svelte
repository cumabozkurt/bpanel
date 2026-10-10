<script>
	// v0.4 obsx: incidents (open → acknowledged → resolved, assignment, history),
	// alert rules and notification channels.
	import { FileWarning } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t } from '$lib/i18n/index.js';
	import { session } from '$lib/stores.js';
	import { showErr, ok, ask } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';
	let tab = $state('incidents');
	let filter = $state('active');
	let incidents = $state([]);
	let sel = $state(null);
	let note = $state('');
	let rules = $state([]);
	let channels = $state([]);
	let chInfo = $state(null);
	let nc = $state({ name: '', kind: 'email', target: '', secret: '', min_severity: 'warning' });
	const when = (ts) => (ts ? new Date(ts * 1000).toLocaleString() : '—');
	async function loadInc() { try { incidents = (await api.get('/admin/obsx/incidents?status=' + filter)).incidents; } catch (e) { showErr(e); } }
	async function open(id) { try { sel = await api.get('/admin/obsx/incidents/' + id); note = ''; } catch (e) { showErr(e); } }
	async function act(action, extra = {}) {
		try {
			const body = { action, ...extra };
			if (note.trim()) body.note = note.trim();
			sel = await api.post('/admin/obsx/incidents/' + sel.incident.id + '/action', body);
			note = '';
			ok('obsx.saved');
			loadInc();
		} catch (e) { showErr(e); }
	}
	async function loadRules() { try { rules = (await api.get('/admin/obsx/rules')).rules; } catch (e) { showErr(e); } }
	async function saveRule(r) {
		try { await api.put('/admin/obsx/rules/' + r.id, { enabled: r.enabled, severity: r.severity, threshold: Number(r.threshold), cooldown_sec: Number(r.cooldown_sec) }); ok('obsx.saved'); } catch (e) { showErr(e); }
	}
	async function loadCh() { try { chInfo = await api.get('/admin/obsx/channels'); channels = chInfo.channels; } catch (e) { showErr(e); } }
	async function addCh(e) {
		e.preventDefault();
		const body = { name: nc.name, kind: nc.kind, target: nc.target, min_severity: nc.min_severity };
		if (nc.kind !== 'email') body.secret = nc.secret;
		try { await api.post('/admin/obsx/channels', body); ok('obsx.saved'); nc = { name: '', kind: 'email', target: '', secret: '', min_severity: 'warning' }; loadCh(); } catch (err) { showErr(err); }
	}
	async function toggleCh(c) { try { await api.put('/admin/obsx/channels/' + c.id, { name: c.name, target: c.target, min_severity: c.min_severity, enabled: !c.enabled }); loadCh(); } catch (e) { showErr(e); } }
	async function testCh(c) { try { await api.post('/admin/obsx/channels/' + c.id + '/test'); ok('obsx.test_sent'); } catch (e) { showErr(e); } loadCh(); }
	async function delCh(c) { if (!ask('obsx.delete_confirm')) return; try { await api.del('/admin/obsx/channels/' + c.id); loadCh(); } catch (e) { showErr(e); } }
	$effect(() => { filter; loadInc(); });
	loadRules();
	loadCh();
	const sev = ['info', 'warning', 'critical'];
</script>

<PageHead title={$t('tools.alerts')} desc={$t('obsx.alerts_desc')} icon={FileWarning} />
<div class="tabs" role="tablist">
	{#each ['incidents', 'rules', 'channels'] as k}
		<button role="tab" class="btn ghost sm" class:active={tab === k} aria-selected={tab === k} onclick={() => (tab = k)}>{$t('obsx.tab_' + k)}</button>
	{/each}
</div>

{#if tab === 'incidents'}
	<div class="card">
		<label>{$t('obsx.filter')}
			<select bind:value={filter}>{#each ['active', 'open', 'acknowledged', 'resolved', 'all'] as f}<option value={f}>{$t('obsx.f_' + f)}</option>{/each}</select>
		</label>
		<table class="table">
			<thead><tr><th>{$t('obsx.severity')}</th><th>{$t('obsx.title')}</th><th>{$t('obsx.status')}</th><th>{$t('obsx.count')}</th><th>{$t('obsx.assignee')}</th><th>{$t('obsx.last_seen')}</th></tr></thead>
			<tbody>
				{#each incidents as i}
					<tr class="click" onclick={() => open(i.id)}>
						<td><span class="badge" class:red={i.severity === 'critical'} class:amber={i.severity === 'warning'}>{$t('obsx.sev_' + i.severity)}</span></td>
						<td>{i.title}</td><td>{$t('obsx.st_' + i.status)}</td><td>{i.count}</td><td>{i.assignee || '—'}</td><td>{when(i.last_at)}</td>
					</tr>
				{:else}<tr><td colspan="6" class="muted">{$t('obsx.no_incidents')}</td></tr>{/each}
			</tbody>
		</table>
	</div>
	{#if sel}
		<div class="card">
			<h3>#{sel.incident.id} {sel.incident.title}</h3>
			<div class="kv small">
				<div>{$t('obsx.rule')}</div><div class="mono">{sel.incident.rule}</div>
				<div>{$t('obsx.status')}</div><div>{$t('obsx.st_' + sel.incident.status)}</div>
				<div>{$t('obsx.first_seen')}</div><div>{when(sel.incident.first_at)}</div>
				<div>{$t('obsx.assignee')}</div><div>{sel.incident.assignee || '—'}</div>
			</div>
			{#if sel.incident.detail}<pre class="mono small">{sel.incident.detail}</pre>{/if}
			<label>{$t('obsx.note')} <input bind:value={note} maxlength="2000" /></label>
			<div class="row">
				{#if sel.incident.status === 'open'}<button class="btn" onclick={() => act('ack')}>{$t('obsx.ack')}</button>{/if}
				{#if sel.incident.status !== 'resolved'}
					<button class="btn" onclick={() => act('assign', { assignee_id: $session?.user?.id })}>{$t('obsx.assign_me')}</button>
					<button class="btn primary" onclick={() => act('resolve')}>{$t('obsx.resolve')}</button>
				{:else}<button class="btn" onclick={() => act('reopen')}>{$t('obsx.reopen')}</button>{/if}
				<button class="btn ghost" disabled={!note.trim()} onclick={() => act('note')}>{$t('obsx.add_note')}</button>
			</div>
			<h4>{$t('obsx.history')}</h4>
			<ul class="small">{#each sel.history as h}<li>{when(h.at)} — <b>{h.actor || $t('obsx.system')}</b> {$t('obsx.h_' + h.action)} {h.note}</li>{/each}</ul>
		</div>
	{/if}
{:else if tab === 'rules'}
	<div class="card">
		<table class="table">
			<thead><tr><th>{$t('obsx.rule')}</th><th>{$t('obsx.enabled')}</th><th>{$t('obsx.severity')}</th><th>{$t('obsx.threshold')}</th><th>{$t('obsx.cooldown')}</th><th></th></tr></thead>
			<tbody>
				{#each rules as r}
					<tr>
						<td>{$t('obsx.r_' + r.id)}</td>
						<td><input type="checkbox" bind:checked={r.enabled} aria-label={$t('obsx.enabled')} /></td>
						<td><select bind:value={r.severity}>{#each sev as s}<option value={s}>{$t('obsx.sev_' + s)}</option>{/each}</select></td>
						<td><input type="number" min="0" bind:value={r.threshold} aria-label={$t('obsx.threshold')} /></td>
						<td><input type="number" min="60" bind:value={r.cooldown_sec} aria-label={$t('obsx.cooldown')} /></td>
						<td><button class="btn sm" onclick={() => saveRule(r)}>{$t('obsx.save')}</button></td>
					</tr>
				{/each}
			</tbody>
		</table>
		<p class="muted small">{$t('obsx.rules_note')}</p>
	</div>
{:else}
	<div class="card">
		<table class="table">
			<thead><tr><th>{$t('obsx.name')}</th><th>{$t('obsx.kind')}</th><th>{$t('obsx.min_severity')}</th><th>{$t('obsx.last_result')}</th><th></th></tr></thead>
			<tbody>
				{#each channels as c}
					<tr>
						<td>{c.name} {#if c.target}<span class="muted small">{c.target}</span>{/if}</td>
						<td>{$t('obsx.k_' + c.kind)}</td><td>{$t('obsx.sev_' + c.min_severity)}</td>
						<td>{c.last_status ? (c.last_status === 'sent' ? $t('obsx.sent') : $t('errors.' + c.last_error)) : '—'}</td>
						<td class="row">
							<button class="btn sm" onclick={() => toggleCh(c)}>{c.enabled ? $t('obsx.disable') : $t('obsx.enable')}</button>
							<button class="btn sm" onclick={() => testCh(c)}>{$t('obsx.test')}</button>
							<button class="btn sm danger" onclick={() => delCh(c)}>{$t('obsx.delete')}</button>
						</td>
					</tr>
				{:else}<tr><td colspan="5" class="muted">{$t('obsx.no_channels')}</td></tr>{/each}
			</tbody>
		</table>
		<p class="muted small">{$t('obsx.webhook_note')}</p>
	</div>
	<form class="card" onsubmit={addCh}>
		<h3>{$t('obsx.add_channel')}</h3>
		<label>{$t('obsx.name')} <input bind:value={nc.name} required maxlength="100" /></label>
		<label>{$t('obsx.kind')} <select bind:value={nc.kind}>{#each ['email', 'telegram', 'slack', 'discord'] as k}<option value={k}>{$t('obsx.k_' + k)}</option>{/each}</select></label>
		{#if nc.kind === 'email' || nc.kind === 'telegram'}<label>{nc.kind === 'email' ? $t('obsx.email_to') : $t('obsx.chat_id')} <input bind:value={nc.target} required /></label>{/if}
		{#if nc.kind !== 'email'}<label>{nc.kind === 'telegram' ? $t('obsx.bot_token') : $t('obsx.webhook_url')} <input type="password" autocomplete="off" bind:value={nc.secret} required /></label>{/if}
		<label>{$t('obsx.min_severity')} <select bind:value={nc.min_severity}>{#each sev as s}<option value={s}>{$t('obsx.sev_' + s)}</option>{/each}</select></label>
		<p class="muted small">{nc.kind === 'email' ? $t('obsx.email_note') : $t('obsx.secret_note')}</p>
		<button class="btn primary" type="submit">{$t('obsx.add')}</button>
	</form>
{/if}

<style>
	.click { cursor: pointer; }
	.row { display: flex; gap: 8px; flex-wrap: wrap; margin: 8px 0; }
	label { display: block; margin: 6px 0; }
</style>
