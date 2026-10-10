<script>
	import { Puzzle } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t } from '$lib/i18n/index.js';
	import { showErr, ok, ask } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';

	// v0.4 appx: free application installer (pinned versions, verified checksums).
	let { only = '' } = $props();
	let catalog = $state([]);
	let installs = $state([]);
	let domains = $state([]);
	let pick = $state(null);
	let form = $state({ domain_id: 0, path: '' });
	let busy = $state(false);
	let result = $state(null);

	async function load() {
		try {
			catalog = (await api.get('/user/installer/catalog')).apps;
			installs = (await api.get('/user/installer/installs')).installs;
			const d = await api.get('/user/domains');
			domains = (d.domains || d || []).filter((x) => x.kind !== 'alias' && !x.redirect);
			if (domains.length && !form.domain_id) form.domain_id = domains[0].id;
		} catch (e) { showErr(e); }
	}
	async function install(e) {
		e.preventDefault();
		busy = true;
		result = null;
		try {
			result = await api.post('/user/installer/install', { app: pick.id, domain_id: Number(form.domain_id), path: form.path });
			ok('appx.installed', { name: pick.name });
			pick = null;
			load();
		} catch (err) { showErr(err); }
		busy = false;
	}
	async function forget(i) {
		if (!ask('appx.confirm_forget')) return;
		try { await api.del('/user/installer/installs/' + i.id); load(); } catch (err) { showErr(err); }
	}
	load();
</script>

<PageHead title={$t('appx.installer_title')} desc={$t('appx.installer_desc')} icon={Puzzle} />
<div class="grid cards">
	{#each catalog.filter((c) => !only || c.id === only) as c}
		<div class="card pad">
			<h3>{c.name} {c.version}</h3>
			<p class="small muted">{c.license} · PHP ≥ {c.min_php || '—'} · <a href={c.homepage} target="_blank" rel="noopener noreferrer">{c.homepage}</a></p>
			{#if c.enabled}
				<p class="small muted"><code title="sha256">{(c.sha256 || '').slice(0, 16)}…</code> {$t('appx.verified')}</p>
				<button class="btn primary" onclick={() => (pick = c)}>{$t('appx.install')}</button>
			{:else}
				<p class="small warn">{$t('appx.disabled')}: {c.disabled_reason}</p>
			{/if}
		</div>
	{/each}
</div>
{#if pick}
	<form class="card pad" onsubmit={install}>
		<h3>{$t('appx.install')} {pick.name} {pick.version}</h3>
		<label class="field"><span>{$t('appx.domain')}</span>
			<select bind:value={form.domain_id}>{#each domains as d}<option value={d.id}>{d.name}</option>{/each}</select></label>
		<label class="field"><span>{$t('appx.subdir')}</span><input bind:value={form.path} placeholder="blog" spellcheck="false" />
			<small class="muted">{$t('appx.subdir_help')}</small></label>
		<p class="small muted">{$t('appx.install_help')}</p>
		<button class="btn primary" disabled={busy || !domains.length}>{busy ? $t('appx.installing') : $t('appx.install')}</button>
		<button type="button" class="btn" onclick={() => (pick = null)}>{$t('common.cancel')}</button>
	</form>
{/if}
{#if result}
	<div class="card pad" role="status">
		<p>{$t('appx.installed_at')} <a href={result.url} target="_blank" rel="noopener noreferrer">{result.url}</a></p>
		{#if result.db_name}<p class="small">{$t('appx.database')}: <code>{result.db_name}</code> · {$t('appx.db_user')}: <code>{result.db_user}</code>
			{#if result.db_password} · {$t('appx.db_password')}: <code>{result.db_password}</code> <small class="warn">{$t('appx.shown_once')}</small>{/if}</p>{/if}
		<p class="small muted">{result.post_install}</p>
	</div>
{/if}
<div class="card">
	<table class="table">
		<thead><tr><th>{$t('appx.app')}</th><th>{$t('appx.url')}</th><th>{$t('appx.database')}</th><th></th></tr></thead>
		<tbody>
			{#each installs.filter((i) => !only || i.app === only) as i}
				<tr><td>{i.app} {i.version}</td><td><a href={i.url} target="_blank" rel="noopener noreferrer">{i.url}</a></td><td>{i.db_name || '—'}</td>
					<td><button class="btn sm" onclick={() => forget(i)}>{$t('appx.forget')}</button></td></tr>
			{:else}
				<tr><td colspan="4" class="muted">{$t('appx.no_installs')}</td></tr>
			{/each}
		</tbody>
	</table>
</div>
