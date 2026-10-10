<script>
	import { Filter, Plus, Trash2 } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t } from '$lib/i18n/index.js';
	import { showErr, ok, ask } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';
	import Modal from '$lib/components/Modal.svelte';
	import MailxStatus from './MailxStatus.svelte';

	let list = $state([]);
	let boxes = $state([]);
	let open = $state(false);
	let busy = $state(false);
	let last = $state(null);
	let form = $state({});

	async function load() {
		try { const r = await api.get('/user/email/filters'); list = r.filters; boxes = r.mailboxes; } catch (e) { showErr(e); }
	}
	load();
	function add() { form = { mailbox_id: boxes[0]?.id, name: '', field: 'from', header: '', op: 'contains', value: '', action: 'move', target: '' }; open = true; }
	async function save(e) {
		e.preventDefault(); busy = true;
		try { last = await api.post('/user/email/filters', { ...form, mailbox_id: Number(form.mailbox_id) }); ok('common.saved'); open = false; load(); }
		catch (err) { showErr(err); }
		busy = false;
	}
	async function del(f) {
		if (!ask('mailx.f_confirm_delete', { name: f.name })) return;
		try { await api.del('/user/email/filters/' + f.id); ok('common.deleted'); load(); } catch (err) { showErr(err); }
	}
	const actLabel = (f) => $t('mailx.act_' + f.action) + (f.target ? ' → ' + f.target : '');
	const fieldLabel = (f) => (f.field === 'header' ? f.header : $t('mailx.field_' + f.field));
</script>

<PageHead title={$t('tools.email_filters')} desc={$t('mailx.f_desc')} icon={Filter}>
	{#snippet actions()}<button class="btn primary" onclick={add} disabled={!boxes.length}><Plus size={16} /> {$t('mailx.f_add')}</button>{/snippet}
</PageHead>

{#if last?.status === 'not_installed'}<p class="badge amber" role="status">{$t('mailx.sieve_not_installed')} {last.reason}</p>{/if}
<section class="card">
	<div class="tw"><table class="table">
		<thead><tr><th>{$t('mailx.mailbox')}</th><th>{$t('mailx.name')}</th><th>{$t('mailx.rule')}</th><th>{$t('mailx.action')}</th><th>{$t('mailx.state')}</th><th><span class="sr-only">{$t('common.actions')}</span></th></tr></thead>
		<tbody>
			{#each list as f}
				<tr>
					<td>{f.email}</td><td><b>{f.name}</b></td>
					<td>{fieldLabel(f)} {$t('mailx.op_' + f.op)} “{f.value}”</td><td>{actLabel(f)}</td>
					<td><MailxStatus status={f.status} reason={f.reason} /></td>
					<td><div class="actions"><button class="linkbtn danger" onclick={() => del(f)}><Trash2 size={13} /> {$t('common.delete')}</button></div></td>
				</tr>
			{:else}<tr><td colspan="6" class="empty">{boxes.length ? $t('common.none') : $t('mailx.no_mailboxes')}</td></tr>{/each}
		</tbody>
	</table></div>
</section>

<Modal bind:open title={$t('mailx.f_add')}>
	<form id="eff" onsubmit={save}>
		<label class="field"><span>{$t('mailx.mailbox')}</span><select bind:value={form.mailbox_id}>{#each boxes as b}<option value={b.id}>{b.email}</option>{/each}</select></label>
		<label class="field"><span>{$t('mailx.name')}</span><input bind:value={form.name} required maxlength="80" /></label>
		<div class="grid2">
			<label class="field"><span>{$t('mailx.field')}</span><select bind:value={form.field}>{#each ['from', 'to', 'subject', 'header'] as x}<option value={x}>{$t('mailx.field_' + x)}</option>{/each}</select></label>
			<label class="field"><span>{$t('mailx.op')}</span><select bind:value={form.op}>{#each ['contains', 'is', 'begins'] as x}<option value={x}>{$t('mailx.op_' + x)}</option>{/each}</select></label>
		</div>
		{#if form.field === 'header'}<label class="field"><span>{$t('mailx.header')}</span><input bind:value={form.header} required pattern="[A-Za-z0-9][A-Za-z0-9\-]*" maxlength="63" placeholder="X-Mailer" /></label>{/if}
		<label class="field"><span>{$t('mailx.value')}</span><input bind:value={form.value} required maxlength="200" /></label>
		<label class="field"><span>{$t('mailx.action')}</span><select bind:value={form.action}>{#each ['move', 'discard', 'redirect'] as x}<option value={x}>{$t('mailx.act_' + x)}</option>{/each}</select></label>
		{#if form.action === 'move'}<label class="field"><span>{$t('mailx.folder')}</span><input bind:value={form.target} required maxlength="100" placeholder="Newsletters" /></label>{/if}
		{#if form.action === 'redirect'}<label class="field"><span>{$t('mailx.redirect_to')}</span><input type="email" bind:value={form.target} required /></label>{/if}
	</form>
	{#snippet footer()}<button class="btn" onclick={() => (open = false)}>{$t('common.cancel')}</button><button class="btn primary" form="eff" disabled={busy}>{$t('common.save')}</button>{/snippet}
</Modal>

<style>.grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }</style>
