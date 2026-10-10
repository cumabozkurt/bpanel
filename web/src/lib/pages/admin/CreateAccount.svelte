<script>
	import { UserPlus, Loader2, CheckCircle2 } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t, languages } from '$lib/i18n/index.js';
	import { session } from '$lib/stores.js';
	import { showErr, qs, warnText } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';
	import PasswordField from '$lib/components/PasswordField.svelte';
	import { translit } from '$lib/search.js';
	import { toAsciiDomain, typedDomainProblem, usernameProblem, domainWasCleaned } from '$lib/validate.js';
	import { customValidity, maxLen } from '$lib/a11y.js';
	import { tick } from 'svelte';
	import { toApi, showLimit, sendWithLimits, noteValues } from '$lib/limits.js';
	import LimitInput from '$lib/components/LimitInput.svelte';

	let all = $state([]);
	let me = $derived($session?.user);
	let isAdmin = $derived(me?.role === 'admin');
	// R2-UX-02: only the administrator creates resellers; a reseller always creates hosting accounts
	let form = $state({ domain: '', username: '', password: '', email: '', package_id: 0, role: qs('role') === 'reseller' && $session?.user?.role === 'admin' ? 'reseller' : 'user', lang: '', web_mode: '' });
	let resLim = $state({ max_accounts: { unl: false, n: 10 }, reseller_disk_mb: { unl: false, n: 10240 } });
	$effect(() => { if (!isAdmin && form.role !== 'user') form.role = 'user'; });
	// R2-UX-03: a reseller sees only its own packages
	let pkgs = $derived(isAdmin ? all : all.filter((p) => p.owner_id === me?.id));
	let successEl = $state();
	let userTouched = $state(false);
	let busy = $state(false);
	let done = $state(null);
	api.get('/admin/packages').then((p) => { all = p; noteValues(p, ['disk_mb', 'max_domains']); form.package_id = pkgs[0]?.id ?? 0; }).catch(showErr);
	let pkg = $derived(pkgs.find((p) => p.id == form.package_id));

	let ascii = $derived(toAsciiDomain(form.domain));
	let domProblem = $derived(form.domain ? typedDomainProblem(form.domain) : null);
	// the first label could not be transliterated (Arabic, emoji…): say why Username stays empty
	let userFromDomainFailed = $derived(!userTouched && !!form.domain.trim() && !domProblem && !form.username);
	let userProblem = $derived(form.username ? usernameProblem(form.username) : null);
	// Auto-username from the domain's first label, transliterated (çiçekçi.com.tr -> cicekci).
	$effect(() => {
		if (!userTouched && form.domain) {
			const first = form.domain.trim().toLowerCase().replace(/^[a-z]+:\/\//, '').replace(/^www\./, '').split('.')[0];
			form.username = translit(first).replace(/^[0-9]+/, '').slice(0, 8);
		}
	});
	async function submit(e) {
		e.preventDefault();
		busy = true; done = null;
		try {
			const body = { ...form, role: isAdmin ? form.role : 'user', domain: ascii, package_id: Number(form.package_id) };
			let r;
			if (body.role === 'reseller') {
				body.max_accounts = toApi(resLim.max_accounts);
				body.reseller_disk_mb = toApi(resLim.reseller_disk_mb);
				r = await sendWithLimits((b) => api.post('/admin/accounts', b), body, ['max_accounts', 'reseller_disk_mb']);
			} else r = await api.post('/admin/accounts', body);
			done = r;
			// R2-UX-08: move focus to the result heading so keyboard and screen-reader users land on it
			await tick();
			successEl?.focus();
		} catch (err) { showErr(err); }
		busy = false;
	}
	const lim = (v) => showLimit(v);
</script>

<PageHead title={form.role === 'reseller' ? $t('tools.create_reseller') : $t('tools.create_account')} desc={$t('newacc.desc')} icon={UserPlus}
	crumbs={{ label: $t('shell.breadcrumbs'), items: [{ href: '/', text: $t('nav.home') }, { href: form.role === 'reseller' ? '/accounts?role=reseller' : '/accounts', text: $t(form.role === 'reseller' ? 'groups.resellers' : 'groups.account_functions') }] }} />

{#if done}
	<div class="alert ok" role="status"><CheckCircle2 size={18} aria-hidden="true" /><div><h2 class="okh" tabindex="-1" bind:this={successEl}>{$t('newacc.success', { user: done.account.username, domain: done.account.primary_domain })}</h2>
		{#each done.warnings ?? [] as w}<div class="small">⚠ {warnText(w)}</div>{/each}
		<div class="row" style="margin-top:8px"><a class="btn sm" href="/accounts">{$t('acc.title')}</a><button class="btn sm" onclick={() => { done = null; form = { ...form, domain: '', username: '', password: '', email: '' }; userTouched = false; }}>{$t('newacc.another')}</button></div></div></div>
{/if}

<form class="layout" onsubmit={submit}>
	<div class="stack">
		<section class="card">
			<div class="card-head"><h2>{$t('newacc.domain_info')}</h2></div>
			<div class="card-body">
				<label class="field"><span>{$t('acc.domain')}</span><input bind:value={form.domain} placeholder="example.com" required autocapitalize="off" spellcheck="false" use:customValidity={domProblem} aria-invalid={domProblem ? 'true' : undefined} />
					{#if form.domain && (ascii !== form.domain.trim().toLowerCase() || domainWasCleaned(form.domain)) && !domProblem}<small>{$t('domains.idn_note', { ascii })}</small>{/if}
					{#if domProblem}<small class="field-err">{$t(domProblem)}</small>{:else}<small>{$t('newacc.domain_help')}</small>{/if}</label>
				<label class="field"><span>{$t('acc.username')}</span><input id="newacc-user" bind:value={form.username} oninput={() => (userTouched = true)} required use:maxLen={16} class="mono" autocapitalize="off" spellcheck="false" use:customValidity={userProblem} aria-invalid={userProblem ? 'true' : undefined} />
					{#if userProblem}<small class="field-err">{$t(userProblem)}</small>{:else if userFromDomainFailed}<small>{$t('newacc.username_manual')}</small>{:else}<small>{$t('newacc.username_help')}</small>{/if}</label>
				<PasswordField bind:value={form.password} id="npw" />
				<label class="field"><span>{$t('newacc.email')}</span><input type="email" bind:value={form.email} placeholder="owner@example.com" /></label>
			</div>
		</section>
		<section class="card">
			<div class="card-head"><h2>{$t('newacc.settings')}</h2></div>
			<div class="card-body grid2">
				<label class="field"><span>{$t('prefs.language')}</span><select bind:value={form.lang}><option value="">{$t('newacc.server_default')}</option>{#each languages as l}<option value={l.code}>{l.name}</option>{/each}</select></label>
				{#if $session?.features?.apache !== false}
					<!-- '' = the server's default web mode; the Apache option is hidden on the minimal (nginx-only) profile -->
					<label class="field"><span>{$t('newacc.web_mode')}</span><select bind:value={form.web_mode}><option value="">{$t('newacc.server_default')}</option><option value="nginx-apache">{$t('newacc.mode_na')}</option><option value="nginx">{$t('newacc.mode_n')}</option></select></label>
				{/if}
				{#if isAdmin}
					<label class="field"><span>{$t('acc.role')}</span><select bind:value={form.role}><option value="user">{$t('acc.role_user')}</option><option value="reseller">{$t('acc.role_reseller')}</option></select></label>
					{#if form.role === 'reseller'}
						<LimitInput id="newacc-maxacc" label={$t('newacc.max_accounts')} bind:value={resLim.max_accounts} help={$t('limits.zero_none_help')} />
						<LimitInput id="newacc-rdisk" label={$t('newacc.reseller_disk')} unit="MB" min={1} bind:value={resLim.reseller_disk_mb} help={$t('newacc.reseller_disk_help')} />
					{/if}
				{/if}
			</div>
		</section>
	</div>
	<aside class="stack">
		<section class="card">
			<div class="card-head"><h2>{$t('acc.package')}</h2></div>
			<div class="card-body">
				<select bind:value={form.package_id} aria-label={$t('acc.package')}>{#each pkgs as p}<option value={p.id}>{p.name}</option>{/each}</select>
				{#if !pkgs.length}<p class="small muted" style="margin:8px 0 0">{$t('newacc.no_packages')} <a href="/packages?new=1">{$t('tools.add_package')}</a></p>{/if}
				{#if pkg}
					<div class="kv small" style="margin-top:12px">
						<div>{$t('pkg.disk')}</div><div>{showLimit(pkg.disk_mb, 'MB')}</div>
						<div>{$t('pkg.bandwidth')}</div><div>{showLimit(pkg.bandwidth_mb, 'MB')}</div>
						<div>{$t('pkg.domains')}</div><div>{lim(pkg.max_domains)}</div>
						<div>{$t('pkg.email')}</div><div>{lim(pkg.max_email)}</div>
						<div>{$t('pkg.db')}</div><div>{lim(pkg.max_db)}</div>
						<div>CPU / RAM</div><div>{pkg.cpu_percent}% / {pkg.memory_mb} MB</div>
					</div>
				{/if}
			</div>
		</section>
		<button class="btn primary big" disabled={busy}>{#if busy}<Loader2 size={16} class="spin" /> {$t('newacc.creating')}{:else}<UserPlus size={16} /> {$t('common.create')}{/if}</button>
	</aside>
</form>

<style>
	.layout { display: grid; grid-template-columns: minmax(0, 1fr) 320px; gap: 20px; align-items: start; }
	.big { width: 100%; height: 42px; }
	.okh { font-size: 14px; font-weight: 700; margin: 0; }
	.okh:focus { outline: 2px solid var(--primary); outline-offset: 2px; }
	@media (max-width: 1000px) { .layout { grid-template-columns: 1fr; } }
</style>
