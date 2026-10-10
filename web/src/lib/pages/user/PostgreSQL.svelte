<script>
	import { Database, Trash2, Plus, KeyRound } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t } from '$lib/i18n/index.js';
	import { showErr, ok, ask } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';

	let res = $state(null);
	let name = $state('');
	let password = $state('');
	let busy = $state(false);
	const installed = $derived(res?.status?.status === 'ok');
	async function load() {
		try { res = await api.get('/user/postgresql'); } catch (err) { showErr(err); }
	}
	async function create(e) {
		e.preventDefault(); busy = true;
		try { await api.post('/user/postgresql', { name: name.trim(), password }); name = ''; password = ''; ok('common.saved'); load(); } catch (err) { showErr(err); }
		busy = false;
	}
	async function del(d) {
		if (!ask('dbx.pg_confirm_delete', { name: d.name })) return;
		try { await api.del('/user/postgresql/' + d.id); ok('common.deleted'); load(); } catch (err) { showErr(err); }
	}
	async function pw(d) {
		const p = prompt($t('dbx.pg_new_password', { name: d.name }));
		if (!p) return;
		try { await api.put('/user/postgresql/' + d.id + '/password', { password: p }); ok('common.saved'); } catch (err) { showErr(err); }
	}
	const size = (b) => (b / 1048576).toFixed(1) + ' MB';
	load();
</script>

<PageHead title={$t('tools.postgresql')} desc={$t('dbx.pg_desc')} icon={Database} />

<section class="card">
	{#if res && !installed}
		<p class="badge amber" role="status">{res.status.status === 'not_installed' ? $t('dbx.pg_not_installed') : $t('dbx.pg_unreachable')} {res.status.reason ?? ''}</p>
	{:else if res}<p><small>{$t('dbx.pg_version', { v: res.status.version })}</small></p>{/if}
	<form class="bar" onsubmit={create}>
		<span class="prefix">{res?.prefix}</span>
		<input bind:value={name} required maxlength="50" pattern="[a-z0-9_]+" placeholder={$t('dbx.pg_name')} aria-label={$t('dbx.pg_name')} disabled={!installed} />
		<input type="password" bind:value={password} required minlength="10" autocomplete="new-password" placeholder={$t('common.password')} aria-label={$t('common.password')} disabled={!installed} />
		<button class="btn" disabled={busy || !installed}><Plus size={15} /> {$t('common.create')}</button>
	</form>
	<p><small>{$t('dbx.pg_help')}</small></p>
	<div class="tw"><table class="table">
		<thead><tr><th>{$t('dbx.pg_name')}</th><th>{$t('dbx.pg_role')}</th><th>{$t('dbx.size')}</th><th>{$t('common.actions')}</th></tr></thead>
		<tbody>
			{#each res?.databases ?? [] as d}
				<tr><td>{d.name}</td><td>{d.role}</td><td>{size(d.size_bytes)}</td>
					<td><button class="btn ghost" onclick={() => pw(d)} aria-label={$t('dbx.pg_change_password')} disabled={!installed}><KeyRound size={15} /></button>
						<button class="btn ghost" onclick={() => del(d)} aria-label={$t('common.delete')} disabled={!installed}><Trash2 size={15} /></button></td></tr>
			{:else}<tr><td colspan="4" class="empty">{$t('common.none')}</td></tr>{/each}
		</tbody>
	</table></div>
</section>

<style>.bar { display: flex; gap: 8px; margin-bottom: 8px; flex-wrap: wrap; align-items: center; } .bar input { flex: 1; min-width: 140px; } .prefix { font-family: monospace; }</style>
