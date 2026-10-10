<script>
	import { Mail, Plus, KeyRound, Trash2, HardDrive, Inbox, Settings2 } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t, fmt } from '$lib/i18n/index.js';
	import { showErr, ok, ask, qs } from '$lib/util.js';
	import { openTool } from '$lib/actions.js';
	import PageHead from '$lib/components/PageHead.svelte';
	import Modal from '$lib/components/Modal.svelte';
	import PasswordField from '$lib/components/PasswordField.svelte';
	import SortTh from '$lib/components/SortTh.svelte';
	import Pager from '$lib/components/Pager.svelte';
	import { TableState } from '$lib/table.svelte.js';
	import { matches } from '$lib/search.js';
	import { EMAIL_LOCAL_PATTERN, emailLocalProblem } from '$lib/validate.js';
	import { customValidity, maxLen } from '$lib/a11y.js';
	import { fromApi, toApi, showLimit, sendWithLimits, noteValues, isUnlimited } from '$lib/limits.js';
	import LimitInput from '$lib/components/LimitInput.svelte';

	let data = $state({ accounts: [], domains: [] });
	let search = $state('');
	let createOpen = $state(qs('new') === '1');
	let pwOpen = $state(false);
	let quotaOpen = $state(false);
	let clientOpen = $state(false);
	let cur = $state(null);
	let busy = $state(false);
	let form = $state({ local: '', domain: '', password: '', quota: { unl: false, n: 1024 } });
	// the package's mailbox quota is the default of a new mailbox
	let quotaSeeded = false;
	// R2-UX-15: a mailbox quota above the package mailbox quota is refused by the API; cap the input
	let pkgCap = $derived(data && typeof data.package_quota_mb === 'number' && data.package_quota_mb > 0 ? data.package_quota_mb : 1e8);
	let pkgUnl = $derived(!(data && typeof data.package_quota_mb === 'number' && data.package_quota_mb > 0));
	let newPw = $state('');
	let newQuota = $state({ unl: false, n: 1024 });

	async function load() { try { data = await api.get('/user/email/accounts'); noteValues(data.accounts, ['quota_mb']); if (!form.domain) form.domain = data.domains[0] ?? ''; if (!quotaSeeded && typeof data.package_quota_mb === 'number') { quotaSeeded = true; form.quota = fromApi(data.package_quota_mb, 1024); } } catch (e) { showErr(e); } }
	load();
	let shown = $derived(data.accounts.filter((a) => !search.trim() || matches(a.email, search)));
	// /email/accounts?sort=-usage (Email Disk Usage tool, R2-UX-34): biggest mailboxes first
	const sortUsage = qs('sort') === '-usage';
	const tbl = new TableState(() => shown, { key: sortUsage ? 'usage' : 'email', dir: sortUsage ? -1 : 1, get: { usage: (a) => a.used_bytes } });
	$effect(() => { search; tbl.reset(); });

	async function create(e) {
		e.preventDefault(); busy = true;
		try {
			const r = await sendWithLimits((b) => api.post('/user/email/accounts', b), { local: form.local.trim(), domain: form.domain, password: form.password, quota_mb: toApi(form.quota) }, ['quota_mb']);
			ok('email.created', { email: r.email }); createOpen = false; form = { ...form, local: '', password: '' }; load();
		}
		catch (err) { showErr(err); }
		busy = false;
	}
	async function setPw(e) {
		e.preventDefault(); busy = true;
		try { await api.put(`/user/email/accounts/${cur.id}/password`, { password: newPw }); ok('email.password_changed'); pwOpen = false; newPw = ''; }
		catch (err) { showErr(err); }
		busy = false;
	}
	async function setQuota(e) {
		e.preventDefault(); busy = true;
		try { await sendWithLimits((b) => api.put(`/user/email/accounts/${cur.id}/quota`, b), { quota_mb: toApi(newQuota) }, ['quota_mb']); ok('common.saved'); quotaOpen = false; load(); }
		catch (err) { showErr(err); }
		busy = false;
	}
	async function del(a) {
		if (!ask('email.confirm_delete', { email: a.email })) return;
		try { await api.del('/user/email/accounts/' + a.id); ok('email.deleted', { email: a.email }); load(); } catch (err) { showErr(err); }
	}
	function pct(a) { return !isUnlimited(a.quota_mb) && a.quota_mb > 0 ? Math.min(100, (a.used_bytes / (a.quota_mb * 1048576)) * 100) : 0; }
</script>

<PageHead title={$t('email.title')} desc={$t('email.desc')} icon={Mail}>
	{#snippet actions()}
		<button class="btn" onclick={() => openTool({ action: 'webmail' })}><Inbox size={15} /> {$t('tools.webmail')}</button>
		<button class="btn primary" onclick={() => (createOpen = true)}><Plus size={16} /> {$t('email.create')}</button>
	{/snippet}
</PageHead>

<div class="card">
	<div class="toolbar">
		<input type="search" placeholder={$t('common.search')} bind:value={search} aria-label={$t('common.search')} />
		<span class="grow"></span><span class="muted small">{$t('common.count', { n: shown.length })}</span>
	</div>
	<div class="tw">
	<table class="table">
		<thead><tr><SortTh {tbl} key="email" label={$t('email.account')} /><SortTh {tbl} key="usage" label={$t('email.storage')} style="width:260px" /><th><span class="sr-only">{$t('common.actions')}</span></th></tr></thead>
		<tbody>
			{#each tbl.page as a}
				<tr>
					<td><b>{a.email}</b></td>
					<td>
						<div class="small">{$fmt.bytes(a.used_bytes)} / {isUnlimited(a.quota_mb) ? '∞' : $fmt.bytes(a.quota_mb * 1048576)}</div>
						<div class="progress" class:warn={pct(a) >= 80} role="progressbar" aria-valuenow={Math.round(pct(a))} aria-valuemin="0" aria-valuemax="100" aria-label={$t('email.storage')}><div style="width:{Math.max(2, pct(a))}%"></div></div>
					</td>
					<td><div class="actions">
						<button class="linkbtn" onclick={() => openTool({ action: 'webmail' })} aria-label={$t('email.check_email_named', { email: a.email })}><Inbox size={13} /> {$t('email.check_email')}</button>
						<button class="linkbtn" onclick={() => { cur = a; clientOpen = true; }} aria-label={$t('email.connect_devices') + ': ' + a.email}><Settings2 size={13} /> {$t('email.connect_devices')}</button>
						<button class="linkbtn" onclick={() => { cur = a; newPw = ''; pwOpen = true; }} aria-label={$t('email.change_password_for', { email: a.email })}><KeyRound size={13} /> {$t('common.password')}</button>
						<button class="linkbtn" onclick={() => { cur = a; newQuota = fromApi(a.quota_mb, 1024); quotaOpen = true; }} aria-label={$t('email.quota') + ': ' + a.email}><HardDrive size={13} /> {$t('email.quota')}</button>
						<button class="linkbtn danger" onclick={() => del(a)} aria-label={$t('email.delete_named', { email: a.email })}><Trash2 size={13} /> {$t('common.delete')}</button>
					</div></td>
				</tr>
			{:else}
				<tr><td colspan="3" class="empty">{$t('email.none')}</td></tr>
			{/each}
		</tbody>
	</table>
	</div>
	<Pager {tbl} />
</div>

<Modal bind:open={createOpen} title={$t('email.create')}>
	<form id="mcreate" onsubmit={create}>
		<label class="field"><span>{$t('email.address')}</span>
			<div class="input-group"><input id="mail-local" bind:value={form.local} placeholder="info" required autocapitalize="off" spellcheck="false" pattern={EMAIL_LOCAL_PATTERN + '|.{64,}'} use:maxLen={63} data-err="errors.invalid_email_local"
					use:customValidity={form.local.includes('..') ? emailLocalProblem(form.local) : null} aria-label={$t('email.address')} /><span class="addon">@</span>
				<select bind:value={form.domain} style="width:auto;border-radius:0 6px 6px 0" aria-label={$t('domains.domain')}>{#each data.domains as d}<option>{d}</option>{/each}</select></div>
		</label>
		<PasswordField bind:value={form.password} id="mpw" />
		<LimitInput id="mail-quota" label={$t('email.quota')} unit="MB" min={1} max={pkgCap} allowUnlimited={pkgUnl} bind:value={form.quota} help={$t('email.quota_help')} />
	</form>
	{#snippet footer()}<button class="btn" onclick={() => (createOpen = false)}>{$t('common.cancel')}</button><button class="btn primary" form="mcreate" disabled={busy}>{$t('common.create')}</button>{/snippet}
</Modal>

<Modal bind:open={pwOpen} title={$t('email.change_password_for', { email: cur?.email })}>
	<form id="mpwf" onsubmit={setPw}><PasswordField bind:value={newPw} id="mpw2" /></form>
	{#snippet footer()}<button class="btn" onclick={() => (pwOpen = false)}>{$t('common.cancel')}</button><button class="btn primary" form="mpwf" disabled={busy}>{$t('common.save')}</button>{/snippet}
</Modal>

<Modal bind:open={quotaOpen} title={$t('email.quota') + ' — ' + (cur?.email ?? '')}>
	<form id="mq" onsubmit={setQuota}><LimitInput id="mail-quota2" label={$t('email.quota')} unit="MB" min={1} max={pkgCap} allowUnlimited={pkgUnl} bind:value={newQuota} help={$t('email.quota_help')} /></form>
	{#snippet footer()}<button class="btn" onclick={() => (quotaOpen = false)}>{$t('common.cancel')}</button><button class="btn primary" form="mq" disabled={busy}>{$t('common.save')}</button>{/snippet}
</Modal>

<Modal bind:open={clientOpen} title={$t('email.client_settings')} width={560}>
	{#if cur}
		{@const host = 'mail.' + cur.email.split('@')[1]}
		<div class="kv small">
			<div>{$t('email.username')}</div><div class="mono">{cur.email}</div>
			<div>{$t('email.incoming')} (IMAP)</div><div class="mono">{host} · 993 SSL/TLS</div>
			<div>{$t('email.incoming')} (POP3)</div><div class="mono">{host} · 995 SSL/TLS</div>
			<div>{$t('email.outgoing')} (SMTP)</div><div class="mono">{host} · 465 SSL/TLS · 587 STARTTLS</div>
			<div>{$t('email.auth')}</div><div>{$t('email.auth_required')}</div>
		</div>
	{/if}
</Modal>
