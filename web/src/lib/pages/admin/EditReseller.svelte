<script>
	// v0.4 adminx: Edit Reseller (limits, allowed packages, ACL subset).
	import { UserCog } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t } from '$lib/i18n/index.js';
	import { showErr, ok, qs } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';
	let resellers = $state([]);
	let sel = $state(qs('id') || '');
	let cur = $state(null);
	let f = $state({ max_accounts: -1, disk_mb: -1, bandwidth_mb: -1, allowed: [], acl: [] });
	async function init() {
		try { resellers = ((await api.get('/admin/accounts?limit=500&role=reseller')).items ?? []).filter((a) => a.role === 'reseller'); if (sel) load(); } catch (e) { showErr(e); }
	}
	init();
	async function load() {
		cur = null;
		if (!sel) return;
		try {
			cur = await api.get('/admin/resellers/' + sel + '/limits');
			const l = cur.limits;
			f = { max_accounts: l.max_accounts, disk_mb: l.disk_mb, bandwidth_mb: l.bandwidth_mb, allowed: [...l.allowed_packages], acl: [...l.acl] };
		} catch (e) { showErr(e); }
	}
	const toggle = (list, v) => (list.includes(v) ? list.filter((x) => x !== v) : [...list, v]);
	async function save(e) {
		e.preventDefault();
		try {
			await api.put('/admin/resellers/' + sel + '/limits', { max_accounts: Number(f.max_accounts), disk_mb: Number(f.disk_mb), bandwidth_mb: Number(f.bandwidth_mb), allowed_packages: f.allowed, acl: f.acl });
			ok('adminx.saved'); load();
		} catch (err) { showErr(err); }
	}
</script>

<PageHead title={$t('tools.edit_reseller')} desc={$t('adminx.reseller_desc')} icon={UserCog} />
<div class="card">
	<label>{$t('adminx.pick_reseller')}
		<select bind:value={sel} onchange={load}>
			<option value="">{$t('adminx.choose')}</option>
			{#each resellers as r}<option value={String(r.id)}>{r.username}</option>{/each}
		</select>
	</label>
</div>
{#if cur}
	<form class="card" onsubmit={save}>
		<p class="muted small">{$t('adminx.used', { accounts: cur.used.accounts, disk: cur.used.disk_mb, bw: cur.used.bandwidth_mb })}</p>
		<label>{$t('adminx.max_accounts')} <input type="number" min="-1" bind:value={f.max_accounts} /></label>
		<label>{$t('adminx.disk_pool')} <input type="number" min="-1" bind:value={f.disk_mb} /></label>
		<label>{$t('adminx.bw_pool')} <input type="number" min="-1" bind:value={f.bandwidth_mb} /></label>
		<p class="muted small">{$t('adminx.pool_hint')}</p>
		<fieldset>
			<legend>{$t('adminx.allowed_packages')}</legend>
			{#each cur.packages as p}<label class="small"><input type="checkbox" checked={f.allowed.includes(p.id)} onchange={() => (f.allowed = toggle(f.allowed, p.id))} /> {p.name}</label>{:else}<p class="muted small">{$t('common.none')}</p>{/each}
			<p class="muted small">{$t('adminx.allowed_hint')}</p>
		</fieldset>
		<fieldset>
			<legend>{$t('adminx.acl')}</legend>
			{#each cur.acl_choices as p}<label class="small"><input type="checkbox" checked={f.acl.includes(p)} onchange={() => (f.acl = toggle(f.acl, p))} /> <code>{p}</code></label>{/each}
			<p class="muted small">{$t('adminx.acl_hint')}</p>
		</fieldset>
		<button class="btn primary" type="submit">{$t('adminx.save')}</button>
	</form>
{/if}

<style>
	fieldset { border: 0; padding: 0; margin: 0 0 16px; display: flex; flex-wrap: wrap; gap: 6px 16px; }
	legend { font-weight: 600; font-size: 13px; margin-bottom: 6px; width: 100%; }
</style>
