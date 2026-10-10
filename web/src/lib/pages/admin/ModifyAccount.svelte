<script>
	// v0.4 adminx: Modify Account (and Change Contact Email with ?focus=email).
	import { UserCog, Contact } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t } from '$lib/i18n/index.js';
	import { showErr, showWarnings, ok, qs } from '$lib/util.js';
	import { session } from '$lib/stores.js';
	import PageHead from '$lib/components/PageHead.svelte';
	const emailOnly = qs('focus') === 'email';
	let accounts = $state([]);
	let packages = $state([]);
	let resellers = $state([]);
	let sel = $state(qs('id') || '');
	let cur = $state(null);
	let f = $state({ package_id: '', owner_id: '', shell_access: false, max_addon_domains: '', max_subdomains: '', email: '', reset: false });
	let isAdmin = $derived($session?.user?.role === 'admin');
	async function init() {
		try {
			const all = (await api.get('/admin/accounts?limit=500')).items ?? [];
			accounts = all.filter((a) => a.role === 'user' || (emailOnly && a.role === 'reseller'));
			resellers = all.filter((a) => a.role === 'reseller');
			const p = await api.get('/admin/packages');
			packages = p.items ?? p.packages ?? p ?? [];
			if (sel) load();
		} catch (e) { showErr(e); }
	}
	init();
	const num = (v) => (v === '' || v === null || v === undefined ? null : Number(v));
	async function load() {
		cur = null;
		if (!sel) return;
		try {
			cur = await api.get('/admin/accounts/' + sel + '/modify');
			f = { package_id: cur.package_id ?? '', owner_id: cur.owner_id ?? '', shell_access: cur.overrides.shell_access,
				max_addon_domains: cur.overrides.max_addon_domains ?? '', max_subdomains: cur.overrides.max_subdomains ?? '', email: cur.email, reset: false };
		} catch (e) { showErr(e); }
	}
	async function save(e) {
		e.preventDefault();
		const body = { email: f.email, version: cur.version };
		if (!emailOnly) {
			if (f.package_id !== '') body.package_id = Number(f.package_id);
			body.shell_access = f.shell_access;
			if (f.reset) body.reset_overrides = true;
			else {
				if (num(f.max_addon_domains) !== null) body.max_addon_domains = num(f.max_addon_domains);
				if (num(f.max_subdomains) !== null) body.max_subdomains = num(f.max_subdomains);
			}
			if (isAdmin && f.owner_id !== '' && Number(f.owner_id) !== cur.owner_id) body.owner_id = Number(f.owner_id);
		}
		try { const r = await api.put('/admin/accounts/' + sel + '/modify', body); showWarnings(r); ok('adminx.saved'); load(); } catch (err) { showErr(err); }
	}
</script>

<PageHead title={$t(emailOnly ? 'tools.change_contact_email' : 'tools.modify_account')} desc={$t(emailOnly ? 'adminx.contact_desc' : 'adminx.modify_desc')} icon={emailOnly ? Contact : UserCog} />
<div class="card">
	<label>{$t('adminx.pick_account')}
		<select bind:value={sel} onchange={load}>
			<option value="">{$t('adminx.choose')}</option>
			{#each accounts as a}<option value={String(a.id)}>{a.username} ({a.primary_domain})</option>{/each}
		</select>
	</label>
</div>
{#if cur}
	<form class="card" onsubmit={save}>
		{#if !emailOnly}
			<label>{$t('adminx.package')}
				<select bind:value={f.package_id}>
					{#each packages as p}<option value={p.id}>{p.name}</option>{/each}
				</select>
			</label>
			{#if isAdmin}
				<label>{$t('adminx.owner')}
					<select bind:value={f.owner_id}>
						<option value={$session?.user?.id}>{$session?.user?.username}</option>
						{#each resellers as r}<option value={r.id}>{r.username}</option>{/each}
					</select>
				</label>
			{:else}<p class="muted small">{$t('adminx.owner_admin_only')}</p>{/if}
			<label class="small"><input type="checkbox" bind:checked={f.shell_access} /> {$t('adminx.shell')}</label>
			<p class="muted small">{$t('adminx.shell_hint')}</p>
			<label>{$t('adminx.max_addon')} <input type="number" min="-1" bind:value={f.max_addon_domains} disabled={f.reset} /></label>
			<label>{$t('adminx.max_sub')} <input type="number" min="-1" bind:value={f.max_subdomains} disabled={f.reset} /></label>
			<p class="muted small">{$t('adminx.override_hint')} {$t('adminx.effective', { addon: cur.effective.max_addon_domains < 0 ? $t('adminx.unlimited') : cur.effective.max_addon_domains, sub: cur.effective.max_subdomains < 0 ? $t('adminx.unlimited') : cur.effective.max_subdomains })}</p>
			<label class="small"><input type="checkbox" bind:checked={f.reset} /> {$t('adminx.reset_overrides')}</label>
			<label>{$t('adminx.primary_domain')} <input value={cur.primary_domain} disabled /></label>
			<p class="muted small">{$t('adminx.rename_unsupported')}</p>
		{/if}
		<label>{$t('adminx.contact_email')} <input type="email" bind:value={f.email} maxlength="254" /></label>
		<button class="btn primary" type="submit">{$t('adminx.save')}</button>
	</form>
{/if}
