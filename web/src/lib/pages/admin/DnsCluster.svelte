<script>
	import { Waypoints } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t } from '$lib/i18n/index.js';
	import { showErr, ok } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';

	let res = $state(null);
	let status = $state(null);
	let checking = $state(false);
	let busy = $state(false);
	let ip = $state('');
	let name = $state('');
	let remote = $state({ name: '', url: '', api_key: '', primary_ip: '' });
	let lastSync = $state(null);

	const stateColor = { in_sync: 'green', behind: 'amber', ahead: 'amber', missing: 'amber', unreachable: 'red', unknown: 'gray' };

	async function load() {
		try { res = await api.get('/admin/dns-cluster'); } catch (e) { showErr(e); }
	}
	async function add(e) {
		e.preventDefault();
		busy = true;
		try { await api.post('/admin/dns-cluster/secondaries', { ip, name }); ip = ''; name = ''; ok('common.saved'); load(); } catch (err) { showErr(err); }
		busy = false;
	}
	async function del(s) {
		if (!confirm($t('clusterx.confirm_remove', { ip: s.ip }))) return;
		busy = true;
		try { await api.del('/admin/dns-cluster/secondaries/' + s.id); load(); } catch (err) { showErr(err); }
		busy = false;
	}
	async function apply() {
		busy = true;
		try { await api.post('/admin/dns-cluster/apply'); ok('clusterx.applied'); load(); } catch (err) { showErr(err); }
		busy = false;
	}
	async function check() {
		checking = true;
		try { status = await api.get('/admin/dns-cluster/status'); } catch (err) { showErr(err); }
		checking = false;
	}
	async function addRemote(e) {
		e.preventDefault();
		try { await api.post('/admin/dns-cluster/remotes', remote); remote = { name: '', url: '', api_key: '', primary_ip: '' }; ok('common.saved'); load(); } catch (err) { showErr(err); }
	}
	async function delRemote(r) {
		if (!confirm($t('clusterx.confirm_remove', { ip: r.name }))) return;
		try { await api.del('/admin/dns-cluster/remotes/' + r.id); load(); } catch (err) { showErr(err); }
	}
	async function syncRemote(r) {
		try { lastSync = await api.post('/admin/dns-cluster/remotes/' + r.id + '/sync'); ok('clusterx.synced'); load(); } catch (err) { showErr(err); }
	}
	load();
</script>

<PageHead title={$t('tools.dns_cluster')} desc={$t('clusterx.dns_desc')} icon={Waypoints} />

{#if res}
<section class="card">
	<h3>{$t('clusterx.secondaries')}</h3>
	{#if res.last_apply}
		<p>
			<span class="badge {res.last_apply.status === 'ok' ? 'green' : 'amber'}">{$t('clusterx.apply_' + (res.last_apply.status || 'unknown'))}</span>
			{#if res.last_apply.reason}<small>{res.last_apply.reason}</small>{/if}
			<small>{$t('clusterx.notified', { n: res.last_apply.notified ?? 0 })}</small>
		</p>
	{/if}
	<table class="table">
		<thead><tr><th>{$t('clusterx.ip')}</th><th>{$t('clusterx.label')}</th><th></th></tr></thead>
		<tbody>
			{#each res.secondaries as s (s.id)}
				<tr><td><code>{s.ip}</code></td><td>{s.name}</td><td><button class="btn ghost" disabled={busy} onclick={() => del(s)}>{$t('common.delete')}</button></td></tr>
			{:else}
				<tr><td colspan="3"><small>{$t('clusterx.none')}</small></td></tr>
			{/each}
		</tbody>
	</table>
	<form class="bar" onsubmit={add}>
		<input bind:value={ip} placeholder="192.0.2.53" aria-label={$t('clusterx.ip')} required />
		<input bind:value={name} placeholder={$t('clusterx.label')} aria-label={$t('clusterx.label')} maxlength="64" />
		<button class="btn" disabled={busy}>{$t('clusterx.add')}</button>
		<button type="button" class="btn ghost" disabled={busy} onclick={apply}>{$t('clusterx.reapply')}</button>
	</form>
	<p><small>{$t('clusterx.how')}</small></p>
</section>

<section class="card">
	<h3>{$t('clusterx.sync_status')}</h3>
	<button class="btn" disabled={checking || !res.secondaries.length} onclick={check}>{checking ? $t('clusterx.checking') : $t('clusterx.check')}</button>
	{#if status}
		<p><small>{$t('clusterx.primary_q', { addr: status.primary })}</small>{#if status.truncated} <span class="badge amber">{$t('clusterx.truncated')}</span>{/if}</p>
		<table class="table">
			<thead><tr><th>{$t('clusterx.zone')}</th><th>{$t('clusterx.serial')}</th>{#each res.secondaries as s}<th><code>{s.ip}</code></th>{/each}</tr></thead>
			<tbody>
				{#each status.zones as z}
					<tr>
						<td>{z.zone}</td><td><code>{z.primary_serial || '—'}</code></td>
						{#each res.secondaries as s}
							<td><span class="badge {stateColor[z.secondaries[s.ip]] ?? 'gray'}">{$t('clusterx.st_' + (z.secondaries[s.ip] ?? 'unknown'))}</span> <small>{z.serials[s.ip] ?? ''}</small></td>
						{/each}
					</tr>
				{:else}
					<tr><td colspan="9"><small>{$t('clusterx.no_zones')}</small></td></tr>
				{/each}
			</tbody>
		</table>
	{/if}
</section>

<section class="card">
	<h3>{$t('clusterx.remotes')}</h3>
	<p><small>{$t('clusterx.remotes_help')}</small></p>
	<table class="table">
		<thead><tr><th>{$t('clusterx.label')}</th><th>URL</th><th>{$t('clusterx.primary_ip')}</th><th>{$t('clusterx.last_sync')}</th><th></th></tr></thead>
		<tbody>
			{#each res.remotes as r (r.id)}
				<tr>
					<td>{r.name}</td><td><code>{r.url}</code></td><td><code>{r.primary_ip}</code></td>
					<td>{r.last_sync ? new Date(r.last_sync * 1000).toLocaleString() : '—'} {#if r.last_error}<span class="badge amber">{r.last_error}</span>{/if}</td>
					<td><button class="btn ghost" onclick={() => syncRemote(r)}>{$t('clusterx.sync')}</button> <button class="btn ghost" onclick={() => delRemote(r)}>{$t('common.delete')}</button></td>
				</tr>
			{:else}
				<tr><td colspan="5"><small>{$t('clusterx.none')}</small></td></tr>
			{/each}
		</tbody>
	</table>
	{#if lastSync}<p><small>{$t('clusterx.sync_result', { created: lastSync.created, existing: lastSync.existing, failed: Object.keys(lastSync.failed ?? {}).length })}</small></p>{/if}
	<form class="bar" onsubmit={addRemote}>
		<input bind:value={remote.name} placeholder={$t('clusterx.label')} aria-label={$t('clusterx.label')} required maxlength="64" />
		<input bind:value={remote.url} placeholder="https://ns2.example.com:8081" aria-label="URL" required />
		<input type="password" bind:value={remote.api_key} placeholder={$t('clusterx.api_key')} aria-label={$t('clusterx.api_key')} required autocomplete="off" />
		<input bind:value={remote.primary_ip} placeholder={$t('clusterx.primary_ip')} aria-label={$t('clusterx.primary_ip')} required />
		<button class="btn">{$t('clusterx.add')}</button>
	</form>
</section>
{/if}

<style>.bar { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin-top: 8px; }</style>
