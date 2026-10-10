<script>
	import { Network, Trash2, Plus } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t } from '$lib/i18n/index.js';
	import { showErr, ok, ask } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';

	let res = $state(null);
	let host = $state('');
	let note = $state('');
	let busy = $state(false);
	async function load() {
		try { res = await api.get('/user/databases/remote'); } catch (err) { showErr(err); }
	}
	async function add(e) {
		e.preventDefault(); busy = true;
		try { await api.post('/user/databases/remote', { host: host.trim(), note: note.trim() }); host = ''; note = ''; ok('common.saved'); load(); } catch (err) { showErr(err); }
		busy = false;
	}
	async function del(h) {
		if (!ask('dbx.confirm_remove_host', { host: h.host })) return;
		try { await api.del('/user/databases/remote/' + h.id); ok('common.deleted'); load(); } catch (err) { showErr(err); }
	}
	load();
</script>

<PageHead title={$t('tools.remote_mysql')} desc={$t('dbx.remote_desc')} icon={Network} />

<section class="card">
	{#if res && !res.enabled}<p class="badge amber" role="status">{$t('dbx.remote_disabled')}</p>{/if}
	<form class="bar" onsubmit={add}>
		<input bind:value={host} required maxlength="60" placeholder={$t('dbx.host_ph')} aria-label={$t('dbx.host')} disabled={!res?.enabled} />
		<input bind:value={note} maxlength="100" placeholder={$t('dbx.note')} aria-label={$t('dbx.note')} disabled={!res?.enabled} />
		<button class="btn" disabled={busy || !res?.enabled}><Plus size={15} /> {$t('dbx.add_host')}</button>
	</form>
	<p><small>{$t('dbx.host_help')}</small></p>
	<div class="tw"><table class="table">
		<thead><tr><th>{$t('dbx.host')}</th><th>{$t('dbx.mysql_host')}</th><th>{$t('dbx.note')}</th><th>{$t('common.actions')}</th></tr></thead>
		<tbody>
			{#each res?.hosts ?? [] as h}
				<tr><td>{h.host}</td><td><code>{h.mysql_host}</code></td><td>{h.note}</td>
					<td><button class="btn ghost" onclick={() => del(h)} aria-label={$t('common.delete')}><Trash2 size={15} /></button></td></tr>
			{:else}<tr><td colspan="4" class="empty">{$t('common.none')}</td></tr>{/each}
		</tbody>
	</table></div>
	{#if res}<p><small>{$t('dbx.remote_note', { port: res.port, n: res.max_hosts })}</small></p>
	<p><small>{$t('dbx.max_conn_info', { n: res.max_user_connections || $t('dbx.unlimited') })}</small></p>{/if}
</section>

<style>.bar { display: flex; gap: 8px; margin-bottom: 8px; flex-wrap: wrap; } .bar input { flex: 1; min-width: 160px; }</style>
