<script>
	import { Webhook, Trash2, Plus } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t } from '$lib/i18n/index.js';
	import { showErr, ok, ask } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';
	import Modal from '$lib/components/Modal.svelte';

	// v0.4 usagex: own API tokens (existing /account/tokens endpoints; creation needs a recent re-auth).
	const PERMS = ['hosting.read', 'hosting.write'];
	let tokens = $state([]);
	let form = $state({ name: '', perms: ['hosting.read'], days: 90, ip_allow: '' });
	let created = $state(null);
	let reauth = $state(false);
	let pw = $state('');

	async function load() {
		try { tokens = (await api.get('/account/tokens')).tokens; } catch (e) { showErr(e); }
	}
	async function create(e) {
		e?.preventDefault();
		const body = { name: form.name.trim(), perms: form.perms, ip_allow: form.ip_allow.split(/[\s,]+/).filter(Boolean) };
		if (Number(form.days) > 0) body.expires_at = Math.floor(Date.now() / 1000) + Number(form.days) * 86400;
		try {
			created = await api.post('/account/tokens', body);
			form.name = '';
			load();
		} catch (err) {
			if (err.code === 'reauth_required') reauth = true; else showErr(err);
		}
	}
	async function confirmReauth(e) {
		e.preventDefault();
		try {
			await api.post('/account/reauth', /^\d{6}$/.test(pw) ? { totp: pw } : { password: pw });
			reauth = false; pw = '';
			create();
		} catch (err) { showErr(err); }
	}
	async function revoke(tk) {
		if (!ask('usagex.tok_revoke_q', { name: tk.name })) return;
		try { await api.del(`/account/tokens/${tk.id}`); ok('usagex.tok_revoked'); load(); } catch (e) { showErr(e); }
	}
	const when = (u) => (u ? new Date(u * 1000).toLocaleString() : '—');
	load();
</script>

<PageHead title={$t('usagex.tok_title')} desc={$t('usagex.tok_desc')} icon={Webhook} />
{#if created}
	<div class="card pad warn" role="status">
		<p>{$t('usagex.tok_once')}</p>
		<code style="word-break:break-all">{created.token}</code>
		<p><button class="btn sm" onclick={() => navigator.clipboard?.writeText(created.token)}>{$t('usagex.tok_copy')}</button> <button class="btn ghost sm" onclick={() => (created = null)}>{$t('common.close')}</button></p>
	</div>
{/if}
<form class="card pad row" onsubmit={create}>
	<label class="field"><span>{$t('usagex.name')}</span><input bind:value={form.name} required maxlength="64" /></label>
	<fieldset class="field"><legend>{$t('usagex.tok_perms')}</legend>
		{#each PERMS as p}<label><input type="checkbox" value={p} bind:group={form.perms} /> {$t('usagex.perm.' + p.replace('.', '_'))}</label>{/each}</fieldset>
	<label class="field"><span>{$t('usagex.tok_expiry')}</span>
		<select bind:value={form.days}><option value={30}>30d</option><option value={90}>90d</option><option value={365}>365d</option><option value={0}>{$t('usagex.tok_never')}</option></select></label>
	<label class="field"><span>{$t('usagex.tok_ips')}</span><input bind:value={form.ip_allow} placeholder="203.0.113.0/24" /></label>
	<button class="btn primary" disabled={!form.perms.length}><Plus size={15} /> {$t('usagex.tok_create')}</button>
</form>
<div class="card tw">
	<table class="table">
		<thead><tr><th>{$t('usagex.name')}</th><th>{$t('usagex.tok_prefix')}</th><th>{$t('usagex.tok_perms')}</th><th>{$t('usagex.tok_last_used')}</th><th>{$t('usagex.tok_expiry')}</th><th>{$t('usagex.tok_status')}</th><th></th></tr></thead>
		<tbody>
			{#each tokens as tk (tk.id)}
				<tr><td>{tk.name}</td><td><code>{tk.prefix}…</code></td><td>{tk.perms.join(', ')}</td><td>{when(tk.last_used_at)}</td><td>{tk.expires_at ? when(tk.expires_at) : $t('usagex.tok_never')}</td><td>{tk.status}</td>
					<td class="right">{#if tk.status === 'active'}<button class="btn ghost sm" aria-label={$t('common.delete')} onclick={() => revoke(tk)}><Trash2 size={14} /></button>{/if}</td></tr>
			{:else}<tr><td colspan="7" class="empty">{$t('usagex.tok_empty')}</td></tr>{/each}
		</tbody>
	</table>
</div>
<Modal bind:open={reauth} title={$t('usagex.tok_reauth')}>
		<form onsubmit={confirmReauth}>
			<p class="small">{$t('errors.reauth_required')}</p>
			<label class="field"><span>{$t('common.password')}</span><input type="password" bind:value={pw} required autocomplete="current-password" /></label>
			<button class="btn primary">{$t('usagex.confirm')}</button>
		</form>
</Modal>
