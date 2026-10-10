<script>
	import { Database } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t } from '$lib/i18n/index.js';
	import { showErr, ok } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';

	let res = $state(null);
	let accounts = $state([]);
	let acc = $state('');
	let limit = $state(0);
	async function load() {
		try { res = await api.get('/admin/dbx/settings'); } catch (err) { showErr(err); }
		try { const a = await api.get('/admin/accounts'); accounts = Array.isArray(a) ? a : (a.accounts ?? a.items ?? []); } catch (err) { /* list is optional */ }
	}
	async function toggle() {
		try { await api.put('/admin/dbx/settings', { remote_enabled: !res.remote_enabled }); ok('common.saved'); load(); } catch (err) { showErr(err); }
	}
	async function pick() {
		if (!acc) return;
		try { limit = (await api.get('/admin/accounts/' + acc + '/db-limits')).max_user_connections; } catch (err) { showErr(err); }
	}
	async function saveLimit(e) {
		e.preventDefault();
		try { await api.put('/admin/accounts/' + acc + '/db-limits', { max_user_connections: Number(limit) }); ok('common.saved'); } catch (err) { showErr(err); }
	}
	load();
</script>

<PageHead title={$t('tools.db_settings')} desc={$t('dbx.admin_desc')} icon={Database} />

{#if res}
<section class="card">
	<h3>{$t('tools.remote_mysql')}</h3>
	<label class="row"><input type="checkbox" checked={res.remote_enabled} onchange={toggle} /> {$t('dbx.remote_switch')}</label>
	<p><small>{$t('dbx.firewall_note', { port: res.mysql_port })}</small></p>
</section>
<section class="card">
	<h3>PostgreSQL</h3>
	<p><span class="badge {res.postgresql.status === 'ok' ? 'green' : 'amber'}">{$t('dbx.engine_' + res.postgresql.status)}</span> {res.postgresql.version ?? ''}</p>
	{#if res.postgresql.status !== 'ok'}<p><small>{$t('dbx.pg_install_hint')}</small></p>{/if}
</section>
<section class="card">
	<h3>{$t('dbx.max_conn')}</h3>
	<form class="bar" onsubmit={saveLimit}>
		<select bind:value={acc} onchange={pick} aria-label={$t('dbx.account')}>
			<option value="">{$t('dbx.account')}</option>
			{#each accounts as a}<option value={String(a.id)}>{a.username}</option>{/each}
		</select>
		<input type="number" min="0" max="10000" bind:value={limit} aria-label={$t('dbx.max_conn')} disabled={!acc} />
		<button class="btn" disabled={!acc}>{$t('common.save')}</button>
	</form>
	<p><small>{$t('dbx.max_conn_help')}</small></p>
</section>
{/if}

<style>.bar { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; } .row { display: flex; gap: 8px; align-items: center; }</style>
