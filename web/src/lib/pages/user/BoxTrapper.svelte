<script>
	// v1.1: BoxTrapper — mail from unknown senders goes to a quarantine folder (Sieve);
	// no challenge mails are sent (no backscatter), the owner releases senders by whitelisting.
	import { ShieldQuestion, Save } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t } from '$lib/i18n/index.js';
	import { showErr, ok } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';
	let boxes = $state([]);
	let sel = $state(null);
	let form = $state(null);
	async function load() {
		try {
			boxes = (await api.get('/user/email/boxtrapper')).mailboxes ?? [];
			if (!boxes.find((b) => b.mailbox_id === sel)) sel = boxes[0]?.mailbox_id ?? null;
			fill();
		} catch (e) { showErr(e); }
	}
	function fill() {
		const b = boxes.find((x) => x.mailbox_id === sel);
		form = b ? { enabled: b.enabled, whitelist: b.whitelist.join('\n'), blacklist: b.blacklist.join('\n'), folder: b.folder || 'BoxTrapper', status: b.status, reason: b.reason } : null;
	}
	const lines = (s) => s.split(/[\s,;]+/).map((x) => x.trim()).filter(Boolean);
	async function save(e) {
		e.preventDefault();
		try {
			await api.put('/user/email/boxtrapper/' + sel, { enabled: form.enabled, whitelist: lines(form.whitelist), blacklist: lines(form.blacklist), folder: form.folder });
			ok('v11.saved');
			load();
		} catch (err) { showErr(err); }
	}
	load();
</script>

<PageHead title={$t('tools.boxtrapper')} desc={$t('v11.boxtrapper_desc')} icon={ShieldQuestion} />
<div class="stack">
	<div class="card"><div class="card-body">
		<label class="field" style="max-width:360px"><span>{$t('mailx.mailbox')}</span>
			<select bind:value={sel} onchange={fill} disabled={!boxes.length}>{#each boxes as b}<option value={b.mailbox_id}>{b.email}</option>{/each}</select></label>
		{#if !boxes.length}<p class="empty">{$t('v11.no_mailboxes')}</p>{/if}
	</div></div>
	{#if form}
		<form class="card" onsubmit={save}><div class="card-body stack">
			<label class="check"><input type="checkbox" bind:checked={form.enabled} /> {$t('v11.boxtrapper_enable')}</label>
			<label class="field"><span>{$t('v11.whitelist')}</span><textarea class="mono" rows="5" bind:value={form.whitelist} placeholder={'friend@example.com\n@partner.example'}></textarea><small>{$t('v11.senders_help')}</small></label>
			<label class="field"><span>{$t('v11.blacklist')}</span><textarea class="mono" rows="4" bind:value={form.blacklist} placeholder="spam@example.net"></textarea><small>{$t('v11.blacklist_help')}</small></label>
			<label class="field" style="max-width:280px"><span>{$t('v11.quarantine_folder')}</span><input bind:value={form.folder} maxlength="64" /></label>
			{#if form.status && form.status !== 'applied'}<p class="muted small">{form.status} {form.reason ?? ''}</p>{/if}
			<p class="muted small">{$t('v11.boxtrapper_note')}</p>
			<div><button class="btn primary"><Save size={14} /> {$t('common.save')}</button></div>
		</div></form>
	{/if}
</div>

<style>.check { display: flex; gap: 8px; align-items: center; }</style>
