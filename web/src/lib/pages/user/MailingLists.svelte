<script>
	import { Users, Plus, Trash2 } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t } from '$lib/i18n/index.js';
	import { showErr, ok, ask } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';
	import Modal from '$lib/components/Modal.svelte';

	let lists = $state([]);
	let domains = $state([]);
	let open = $state(false);
	let busy = $state(false);
	let form = $state({ name: '', domain: '', owner: '' });
	let cur = $state(null);
	let subs = $state(null);
	let addr = $state('');

	async function load() {
		try {
			lists = (await api.get('/user/lists')).lists;
			domains = (await api.get('/user/domains')).filter((d) => d.kind !== 'sub').map((d) => d.name);
		} catch (e) { showErr(e); }
	}
	load();
	function add() { form = { name: '', domain: domains[0] || '', owner: '' }; open = true; }
	async function save(e) {
		e.preventDefault(); busy = true;
		try { await api.post('/user/lists', form); ok('common.saved'); open = false; load(); } catch (err) { showErr(err); }
		busy = false;
	}
	async function del(l) {
		if (!ask('dnsx.ml_delete_q', { address: l.address })) return;
		try { await api.del('/user/lists/' + l.id); ok('common.deleted'); if (cur?.id === l.id) cur = null; load(); } catch (err) { showErr(err); }
	}
	async function show(l) {
		cur = l; subs = null;
		try { subs = await api.get('/user/lists/' + l.id + '/subscribers'); } catch (err) { showErr(err); }
	}
	async function sub(e) {
		e.preventDefault();
		try { subs = await api.post('/user/lists/' + cur.id + '/subscribers', { address: addr }); addr = ''; ok('common.saved'); } catch (err) { showErr(err); }
	}
	async function unsub(a) {
		if (!ask('dnsx.ml_sub_del_q', { address: a })) return;
		try { subs = await api.del('/user/lists/' + cur.id + '/subscribers?address=' + encodeURIComponent(a)); ok('common.deleted'); } catch (err) { showErr(err); }
	}
</script>

<PageHead title={$t('tools.mailing_lists')} desc={$t('dnsx.ml_desc')} icon={Users}>
	{#snippet actions()}<button class="btn primary" onclick={add} disabled={!domains.length}><Plus size={16} /> {$t('dnsx.ml_create')}</button>{/snippet}
</PageHead>

<section class="card">
	<p class="muted">{$t('dnsx.ml_help')}</p>
	<div class="tw"><table class="table">
		<thead><tr><th>{$t('dnsx.ml_name')}</th><th>{$t('dnsx.ml_owner')}</th><th><span class="sr-only">{$t('common.actions')}</span></th></tr></thead>
		<tbody>{#each lists as l}<tr>
			<td><button class="linkbtn" onclick={() => show(l)}><b>{l.address}</b></button></td><td>{l.owner}</td>
			<td><div class="actions"><button class="linkbtn" onclick={() => show(l)}>{$t('dnsx.ml_subs')}</button><button class="linkbtn danger" onclick={() => del(l)}><Trash2 size={13} /> {$t('common.delete')}</button></div></td></tr>
		{:else}<tr><td colspan="3" class="empty">{$t('dnsx.ml_empty')}</td></tr>{/each}</tbody>
	</table></div>
</section>

{#if cur}
	<section class="card">
		<h3>{$t('dnsx.ml_subs')}: {cur.address}</h3>
		{#if subs?.status === 'not_installed'}<p class="badge amber" role="status">{$t('errors.mlist_not_installed')} {subs.reason}</p>{/if}
		<form class="row" onsubmit={sub}>
			<input type="email" bind:value={addr} required maxlength="254" placeholder={$t('dnsx.ml_sub_addr')} aria-label={$t('dnsx.ml_sub_addr')} />
			<button class="btn primary">{$t('dnsx.ml_sub_add')}</button>
		</form>
		<ul>{#each subs?.subscribers || [] as a}<li>{a} <button class="linkbtn danger" onclick={() => unsub(a)}><Trash2 size={13} /> {$t('common.delete')}</button></li>
		{:else}<li class="empty">{$t('dnsx.ml_subs_empty')}</li>{/each}</ul>
	</section>
{/if}

<Modal bind:open title={$t('dnsx.ml_create')}>
	<form id="mlf" onsubmit={save}>
		<label class="field"><span>{$t('dnsx.ml_name')}</span><input bind:value={form.name} required maxlength="48" pattern="[a-z0-9][a-z0-9._\-]*" placeholder="news" /></label>
		<label class="field"><span>{$t('dnsx.ml_domain')}</span><select bind:value={form.domain}>{#each domains as d}<option value={d}>{d}</option>{/each}</select></label>
		<label class="field"><span>{$t('dnsx.ml_owner')}</span><input type="email" bind:value={form.owner} required maxlength="254" /></label>
	</form>
	{#snippet footer()}<button class="btn" onclick={() => (open = false)}>{$t('common.cancel')}</button><button class="btn primary" form="mlf" disabled={busy}>{$t('common.save')}</button>{/snippet}
</Modal>

<style>.row { display: flex; gap: 8px; margin: 8px 0; }</style>
