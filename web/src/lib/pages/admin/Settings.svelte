<script>
	import { Settings } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t, languages } from '$lib/i18n/index.js';
	import { showErr, ok, showWarnings } from '$lib/util.js';
	import { customValidity } from '$lib/a11y.js';
	import { IPV4_RE, domainProblem } from '$lib/validate.js';
	import PageHead from '$lib/components/PageHead.svelte';
	let s = $state(null);
	api.get('/admin/settings').then((r) => (s = r)).catch(showErr);
	// R2-UX-40: commas, semicolons, spaces and new lines all separate name servers; the rule
	// ("at least two") and the copy now agree, and the server IP is checked as IPv4 in place.
	let nsList = $derived((s?.nameservers ?? '').split(/[\s,;]+/).map((x) => x.trim().toLowerCase().replace(/\.$/, '')).filter(Boolean));
	let nsProblem = $derived(!s?.nameservers?.trim() ? null : nsList.length < 2 || nsList.some((n) => domainProblem(n)) ? 'set.nameservers_invalid' : null);
	let ipProblem = $derived(s?.server_ip?.trim() && !IPV4_RE.test(s.server_ip.trim()) ? 'errors.invalid_ipv4' : null);
	async function save(e) {
		e.preventDefault();
		if (nsProblem || ipProblem) return;
		try {
			const r = await api.put('/admin/settings', { default_lang: s.default_lang, nameservers: nsList.join(' '), server_ip: s.server_ip.trim(), acme_email: s.acme_email, contact_email: s.contact_email });
			// one toast: the warning already says "Saved. …" when there is one
			if (r?.warnings?.length) showWarnings(r); else ok('common.saved');
		} catch (err) { showErr(err); }
	}
</script>

<PageHead title={$t('tools.basic_setup')} desc={$t('set.desc')} icon={Settings} crumbs={{ label: $t('shell.breadcrumbs'), items: [{ href: '/', text: $t('nav.home') }, { text: $t('groups.server_config') }] }} />
{#if s}
	<form class="card" onsubmit={save} style="max-width:760px">
		<div class="card-body">
			<label class="field"><span>{$t('set.default_lang')}</span>
				<select bind:value={s.default_lang}>{#each languages as l}<option value={l.code}>{l.name}</option>{/each}</select>
				<small>{$t('set.default_lang_help')}</small></label>
			<label class="field"><span>{$t('set.contact_email')}</span><input type="email" bind:value={s.contact_email} /><small>{$t('set.contact_help')}</small></label>
			<label class="field"><span>{$t('set.acme_email')}</span><input type="email" bind:value={s.acme_email} /><small>{$t('set.acme_help')}</small></label>
			<label class="field"><span>{$t('set.server_ip')}</span><input bind:value={s.server_ip} class="mono" inputmode="decimal" use:customValidity={ipProblem} aria-invalid={ipProblem ? 'true' : undefined} />
				{#if ipProblem}<small class="field-err">{$t(ipProblem)}</small>{:else}<small>{$t('set.server_ip_help')}</small>{/if}</label>
			<label class="field"><span>{$t('set.nameservers')}</span><input bind:value={s.nameservers} placeholder={s.nameservers_suggested} class="mono" use:customValidity={nsProblem} aria-invalid={nsProblem ? 'true' : undefined} />
				{#if nsProblem}<small class="field-err">{$t(nsProblem)}</small>{:else}<small>{$t('set.nameservers_help')}</small>{/if}</label>
			<button class="btn primary">{$t('common.save')}</button>
		</div>
	</form>
{/if}
