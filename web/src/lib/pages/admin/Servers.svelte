<script>
	import { Server } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t } from '$lib/i18n/index.js';
	import { showErr, ok } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';

	let res = $state(null);
	let name = $state('');
	let address = $state('');
	let roles = $state({ web: true });
	let issued = $state(null);
	let selected = $state({});
	let bundle = $state('firewall');
	let pushRes = $state(null);
	let jobs = $state({});

	async function load() {
		try { res = await api.get('/admin/servers'); } catch (err) { showErr(err); }
	}
	async function create(e) {
		e.preventDefault();
		const rl = Object.keys(roles).filter((k) => roles[k]);
		try {
			const r = await api.post('/admin/servers', { name, address, roles: rl });
			issued = { name: r.node.name, token: r.token, command: r.command, expires_at: r.expires_at };
			name = ''; address = '';
			load();
		} catch (err) { showErr(err); }
	}
	async function rotate(n) {
		try { const r = await api.post('/admin/servers/' + n.id + '/rotate'); issued = { name: n.name, token: r.token, command: r.command, expires_at: r.expires_at }; } catch (err) { showErr(err); }
	}
	async function revoke(n) {
		if (!confirm($t('msrv.revoke_confirm', { name: n.name }))) return;
		try { await api.post('/admin/servers/' + n.id + '/revoke'); ok('msrv.revoked'); load(); } catch (err) { showErr(err); }
	}
	async function check(n) {
		try { await api.post('/admin/servers/' + n.id + '/health'); load(); } catch (err) { showErr(err); }
	}
	async function checkAll() {
		try { await api.post('/admin/servers/health'); load(); } catch (err) { showErr(err); }
	}
	async function setAddr(n) {
		const a = prompt($t('msrv.address'), n.address);
		if (a === null) return;
		try { await api.put('/admin/servers/' + n.id, { address: a }); ok('common.saved'); load(); } catch (err) { showErr(err); }
	}
	async function push(e) {
		e.preventDefault();
		const ids = Object.keys(selected).filter((k) => selected[k]).map(Number);
		if (!ids.length) return;
		try { pushRes = (await api.post('/admin/servers/push', { bundle, node_ids: ids })).jobs; ok('msrv.push_queued'); } catch (err) { showErr(err); }
	}
	async function showJobs(n) {
		try { jobs = { ...jobs, [n.id]: (await api.get('/admin/servers/' + n.id + '/jobs')).jobs }; } catch (err) { showErr(err); }
	}
	const when = (s) => (s ? new Date(s * 1000).toLocaleString() : '—');
	load();
</script>

<PageHead title={$t('tools.servers')} desc={$t('msrv.desc')} icon={Server} />

{#if res}
<section class="card">
	<h3>{$t('msrv.ca')}</h3>
	{#if res.ca_status === 'ok'}
		<p><small>{$t('msrv.ca_fp')}</small> <code class="fp">{res.ca_fingerprint}</code></p>
	{:else}
		<p><span class="badge amber">{$t('msrv.ca_unavailable')}</span></p>
	{/if}
</section>

<section class="card">
	<h3>{$t('msrv.add')}</h3>
	<form class="bar" onsubmit={create}>
		<input placeholder={$t('msrv.name')} aria-label={$t('msrv.name')} bind:value={name} required />
		<input placeholder="203.0.113.10:8445" aria-label={$t('msrv.address')} bind:value={address} />
		{#each res.roles as r}<label class="row"><input type="checkbox" bind:checked={roles[r]} /> {$t('msrv.role_' + r)}</label>{/each}
		<button class="btn">{$t('msrv.create_token')}</button>
	</form>
	<p><small>{$t('msrv.add_help')}</small></p>
	{#if issued}
		<div class="issued">
			<p>{$t('msrv.token_once', { name: issued.name, time: when(issued.expires_at) })}</p>
			<pre>{issued.command}</pre>
		</div>
	{/if}
</section>

<section class="card">
	<div class="bar"><h3>{$t('msrv.nodes')}</h3><button class="btn ghost" onclick={checkAll}>{$t('msrv.check_all')}</button></div>
	{#if !res.nodes.length}<p>{$t('common.none')}</p>{:else}
	<div class="tablewrap"><table>
		<thead><tr><th></th><th>{$t('msrv.name')}</th><th>{$t('msrv.address')}</th><th>{$t('msrv.roles')}</th><th>{$t('msrv.status')}</th><th>{$t('msrv.health')}</th><th>{$t('msrv.latency')}</th><th>{$t('msrv.version')}</th><th>{$t('msrv.cert_expiry')}</th><th></th></tr></thead>
		<tbody>
		{#each res.nodes as n}
			<tr>
				<td><input type="checkbox" aria-label={n.name} bind:checked={selected[n.id]} disabled={n.status !== 'active'} /></td>
				<td>{n.name}</td>
				<td><code>{n.address || '—'}</code></td>
				<td>{n.roles.map((r) => $t('msrv.role_' + r)).join(', ')}</td>
				<td><span class="badge {n.status === 'active' ? 'green' : n.status === 'revoked' ? 'red' : 'amber'}">{$t('msrv.st_' + n.status)}</span></td>
				<td><span class="badge {n.health === 'ok' ? 'green' : n.health === 'down' ? 'red' : ''}" title={n.health_error}>{$t('msrv.h_' + n.health)}</span></td>
				<td>{n.latency_ms >= 0 ? n.latency_ms + ' ms' : '—'}</td>
				<td>{n.version || '—'}</td>
				<td>{when(n.cert_not_after)}</td>
				<td class="acts">
					{#if n.status !== 'revoked'}
						<button class="btn ghost" onclick={() => check(n)}>{$t('msrv.check')}</button>
						<button class="btn ghost" onclick={() => setAddr(n)}>{$t('common.edit')}</button>
						<button class="btn ghost" onclick={() => rotate(n)}>{$t('msrv.rotate')}</button>
						<button class="btn ghost" onclick={() => showJobs(n)}>{$t('msrv.jobs')}</button>
						<button class="btn danger" onclick={() => revoke(n)}>{$t('msrv.revoke')}</button>
					{/if}
				</td>
			</tr>
			{#if jobs[n.id]}
				<tr><td colspan="10">
					{#if !jobs[n.id].length}{$t('common.none')}{/if}
					{#each jobs[n.id] as j}<div><code>{j.id}</code> {j.kind} <span class="badge {j.status === 'succeeded' ? 'green' : j.status === 'failed' ? 'red' : 'amber'}">{j.status}</span> {j.error}</div>{/each}
				</td></tr>
			{/if}
		{/each}
		</tbody>
	</table></div>
	{/if}
</section>

<section class="card">
	<h3>{$t('msrv.push')}</h3>
	<form class="bar" onsubmit={push}>
		<select bind:value={bundle} aria-label={$t('msrv.bundle')}>
			{#each res.bundles as b}<option value={b}>{$t('msrv.bundle_' + b)}</option>{/each}
		</select>
		<button class="btn">{$t('msrv.push_selected')}</button>
	</form>
	<p><small>{$t('msrv.push_help')}</small></p>
	{#if pushRes}
		{#each pushRes as p}<div>#{p.node_id}: {#if p.job_id}<code>{p.job_id}</code>{:else}<span class="badge red">{p.error}</span>{/if}</div>{/each}
	{/if}
</section>
{/if}

<style>
	.bar { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
	.row { display: flex; gap: 4px; align-items: center; }
	.fp { word-break: break-all; }
	.issued pre { white-space: pre-wrap; word-break: break-all; }
	.acts { display: flex; gap: 4px; flex-wrap: wrap; }
</style>
