<script>
	import { Reply, Plus, Trash2, Pencil } from '@lucide/svelte';
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
		try { const r = await api.get('/user/email/autoresponders'); list = r.autoresponders; boxes = r.mailboxes; } catch (e) { showErr(e); }
	}
	load();
	function edit(a) {
		form = a ? { ...a } : { mailbox_id: boxes[0]?.id, subject: '', body: '', start: '', end: '', interval_days: 1, from: '', enabled: true };
		open = true;
	}
	async function save(e) {
		e.preventDefault(); busy = true;
		try {
			last = await api.put('/user/email/autoresponders/' + form.mailbox_id, { subject: form.subject, body: form.body, start: form.start, end: form.end,
				interval_days: Number(form.interval_days), from: form.from, enabled: form.enabled });
			ok('common.saved'); open = false; load();
		} catch (err) { showErr(err); }
		busy = false;
	}
	async function del(a) {
		if (!ask('mailx.ar_confirm_delete', { email: a.email })) return;
		try { await api.del('/user/email/autoresponders/' + a.mailbox_id); ok('common.deleted'); load(); } catch (err) { showErr(err); }
	}
</script>

<PageHead title={$t('tools.autoresponders')} desc={$t('mailx.ar_desc')} icon={Reply}>
	{#snippet actions()}<button class="btn primary" onclick={() => edit(null)} disabled={!boxes.length}><Plus size={16} /> {$t('mailx.ar_add')}</button>{/snippet}
</PageHead>

{#if last?.status === 'not_installed'}<p class="badge amber" role="status">{$t('mailx.sieve_not_installed')} {last.reason}</p>{/if}
<section class="card">
	<div class="tw"><table class="table">
		<thead><tr><th>{$t('mailx.mailbox')}</th><th>{$t('mailx.subject')}</th><th>{$t('mailx.period')}</th><th>{$t('mailx.state')}</th><th><span class="sr-only">{$t('common.actions')}</span></th></tr></thead>
		<tbody>
			{#each list as a}
				<tr>
					<td><b>{a.email}</b></td><td>{a.subject}</td>
					<td>{a.start || '…'} – {a.end || '…'} · {$t('mailx.every_days', { n: a.interval_days })}</td>
					<td>{#if !a.enabled}<span class="badge">{$t('mailx.disabled')}</span>{:else}<MailxStatus status={a.status} reason={a.reason} />{/if}</td>
					<td><div class="actions">
						<button class="linkbtn" onclick={() => edit(a)}><Pencil size={13} /> {$t('common.edit')}</button>
						<button class="linkbtn danger" onclick={() => del(a)}><Trash2 size={13} /> {$t('common.delete')}</button>
					</div></td>
				</tr>
			{:else}<tr><td colspan="5" class="empty">{boxes.length ? $t('common.none') : $t('mailx.no_mailboxes')}</td></tr>{/each}
		</tbody>
	</table></div>
</section>

<Modal bind:open title={$t('mailx.ar_add')}>
	<form id="arf" onsubmit={save}>
		<label class="field"><span>{$t('mailx.mailbox')}</span><select bind:value={form.mailbox_id}>{#each boxes as b}<option value={b.id}>{b.email}</option>{/each}</select></label>
		<label class="field"><span>{$t('mailx.subject')}</span><input bind:value={form.subject} required maxlength="200" /></label>
		<label class="field"><span>{$t('mailx.body')}</span><textarea bind:value={form.body} required maxlength="8000" rows="6"></textarea></label>
		<div class="grid2">
			<label class="field"><span>{$t('mailx.start')}</span><input type="date" bind:value={form.start} /></label>
			<label class="field"><span>{$t('mailx.end')}</span><input type="date" bind:value={form.end} /></label>
		</div>
		<label class="field"><span>{$t('mailx.interval')}</span><input type="number" min="1" max="30" bind:value={form.interval_days} required /></label>
		<label class="field"><span>{$t('mailx.from')}</span><input type="email" bind:value={form.from} placeholder={$t('mailx.from_hint')} /></label>
		<label class="r"><input type="checkbox" bind:checked={form.enabled} /> {$t('mailx.enabled')}</label>
	</form>
	{#snippet footer()}<button class="btn" onclick={() => (open = false)}>{$t('common.cancel')}</button><button class="btn primary" form="arf" disabled={busy}>{$t('common.save')}</button>{/snippet}
</Modal>

<style>.r { display: flex; gap: 8px; align-items: center; } .grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }</style>
