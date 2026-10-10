<script>
	import { ShieldAlert } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t } from '$lib/i18n/index.js';
	import { showErr, ok } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';
	import MailxStatus from './MailxStatus.svelte';

	let st = $state(null);
	let form = $state({ enabled: true, required_score: 6, allow: '', deny: '' });
	let busy = $state(false);
	async function load() {
		try {
			st = await api.get('/user/email/spam');
			form = { enabled: st.policy.enabled, required_score: st.policy.required_score, allow: st.policy.allow.join('\n'), deny: st.policy.deny.join('\n') };
		} catch (e) { showErr(e); }
	}
	load();
	const lines = (s) => s.split(/[\n,]+/).map((x) => x.trim()).filter(Boolean);
	async function save(e) {
		e.preventDefault(); busy = true;
		try {
			const r = await api.put('/user/email/spam', { enabled: form.enabled, required_score: Number(form.required_score), allow: lines(form.allow), deny: lines(form.deny) });
			st = { ...st, ...r }; ok('common.saved');
		} catch (err) { showErr(err); }
		busy = false;
	}
</script>

<PageHead title={$t('tools.spam_filters')} desc={$t('mailx.s_desc')} icon={ShieldAlert} />

<section class="card">
	{#if st?.status}<p><MailxStatus status={st.status} reason={st.reason} /> {#if st.status === 'not_installed'}{$t('mailx.rspamd_not_installed')} {st.reason}{/if}</p>{/if}
	{#if st && !st.domains.length}<p class="empty">{$t('mailx.no_domains')}</p>{/if}
	<form onsubmit={save}>
		<label class="r"><input type="checkbox" bind:checked={form.enabled} /> {$t('mailx.s_enabled')}</label>
		<label class="field"><span>{$t('mailx.s_score')}</span><input type="number" min="1" max="30" step="0.5" bind:value={form.required_score} required disabled={!form.enabled} /><small>{$t('mailx.s_score_hint')}</small></label>
		<label class="field"><span>{$t('mailx.s_allow')}</span><textarea rows="4" bind:value={form.allow} placeholder="friend@example.com&#10;@partner.com"></textarea></label>
		<label class="field"><span>{$t('mailx.s_deny')}</span><textarea rows="4" bind:value={form.deny} placeholder="@spammer.biz"></textarea></label>
		<small>{$t('mailx.s_list_hint')}</small>
		<div><button class="btn primary" disabled={busy || !st?.domains.length}>{$t('common.save')}</button></div>
	</form>
</section>

<style>.r { display: flex; gap: 8px; align-items: center; margin-bottom: 10px; } form { display: grid; gap: 10px; }</style>
