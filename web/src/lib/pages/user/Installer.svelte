<script>
	import { Puzzle, Search, Database, FileText, ShieldCheck, ExternalLink, CheckCircle2, X } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t } from '$lib/i18n/index.js';
	import { showErr, ok, ask } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';

	// Application Installer (v1.2): free, open-source apps with pinned versions and
	// verified checksums; searchable, grouped by category, EN/TR descriptions.
	let { only = '' } = $props();
	let catalog = $state([]);
	let installs = $state([]);
	let domains = $state([]);
	let pick = $state(null);
	let form = $state({ domain_id: 0, path: '' });
	let busy = $state(false);
	let result = $state(null);
	let q = $state('');
	let cat = $state('');
	let formEl = $state(null);

	// a translated text when the key exists, the server's English text otherwise
	const tx = (key, fallback) => { const s = $t(key); return s === key ? fallback : s; };
	let base = $derived(catalog.filter((c) => !only || c.id === only));
	let cats = $derived([...new Set(base.map((c) => c.category).filter(Boolean))]);
	let shown = $derived(base.filter((c) => (!cat || c.category === cat) && (!q.trim() || (c.name + ' ' + tx('appx.desc_' + c.id, '') + ' ' + c.category).toLowerCase().includes(q.trim().toLowerCase()))));
	let installedIds = $derived(new Set(installs.map((i) => i.app)));
	const initials = (n) => n.replace(/[^A-Za-z0-9 ]/g, '').split(/\s+/).map((w) => w[0]).join('').slice(0, 2).toUpperCase();
	const hue = (id) => [...id].reduce((h, ch) => (h * 31 + ch.charCodeAt(0)) % 360, 7);

	async function load() {
		try {
			catalog = (await api.get('/user/installer/catalog')).apps;
			installs = (await api.get('/user/installer/installs')).installs;
			const d = await api.get('/user/domains');
			domains = (d.domains || d || []).filter((x) => x.kind !== 'alias' && !x.redirect);
			if (domains.length && !form.domain_id) form.domain_id = domains[0].id;
		} catch (e) { showErr(e); }
	}
	function choose(c) {
		pick = c;
		result = null;
		queueMicrotask(() => formEl?.scrollIntoView({ behavior: 'smooth', block: 'center' }));
	}
	async function install(e) {
		e.preventDefault();
		busy = true;
		result = null;
		try {
			result = { ...(await api.post('/user/installer/install', { app: pick.id, domain_id: Number(form.domain_id), path: pick.root_only ? '' : form.path })), name: pick.name };
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

{#if result}
	<div class="alert ok result" role="status">
		<CheckCircle2 size={18} aria-hidden="true" />
		<div class="grow">
			<p class="rt"><strong>{$t('appx.installed', { name: result.name })}</strong> <a href={result.url} target="_blank" rel="noopener noreferrer">{result.url} <ExternalLink size={12} aria-hidden="true" /></a></p>
			{#if result.db_name}
				<dl class="creds">
					<dt>{$t('appx.database')}</dt><dd><code>{result.db_name}</code></dd>
					<dt>{$t('appx.db_user')}</dt><dd><code>{result.db_user}</code></dd>
					{#if result.db_password}<dt>{$t('appx.db_password')}</dt><dd><code>{result.db_password}</code> <small class="warn">{$t('appx.shown_once')}</small></dd>{/if}
					{#if result.db_host}<dt>{$t('appx.db_host')}</dt><dd><code>{result.db_host}</code></dd>{/if}
				</dl>
			{/if}
			<p class="small"><strong>{$t('appx.next_steps')}:</strong> {tx('appx.post_' + result.app, result.post_install)}</p>
		</div>
		<button class="btn ghost sm" aria-label={$t('common.cancel')} onclick={() => (result = null)}><X size={14} /></button>
	</div>
{/if}

{#if pick}
	<form class="card pad installform" bind:this={formEl} onsubmit={install}>
		<div class="row fh">
			<span class="logo" style="--h:{hue(pick.id)}" aria-hidden="true">{initials(pick.name)}</span>
			<div class="grow"><h2>{$t('appx.install')} {pick.name} <span class="muted ver">{pick.version}</span></h2>
				<p class="muted small">{tx('appx.desc_' + pick.id, '')}</p></div>
		</div>
		<div class="grid2">
			<label class="field"><span>{$t('appx.domain')}</span>
				<select bind:value={form.domain_id}>{#each domains as d}<option value={d.id}>{d.name}</option>{/each}</select></label>
			{#if pick.root_only}
				<div class="field"><span class="lbl">{$t('appx.subdir')}</span><p class="small muted">{$t('appx.root_only_hint')}</p></div>
			{:else}
				<label class="field"><span>{$t('appx.subdir')}</span><input bind:value={form.path} placeholder="blog" spellcheck="false" />
					<small>{$t('appx.subdir_help')}</small></label>
			{/if}
		</div>
		<p class="small muted">{pick.needs_db ? $t('appx.install_help') : $t('appx.install_help_nodb')}</p>
		<div class="row">
			<button class="btn primary" disabled={busy || !domains.length}>{busy ? $t('appx.installing') : $t('appx.install')}</button>
			<button type="button" class="btn" onclick={() => (pick = null)}>{$t('common.cancel')}</button>
		</div>
	</form>
{/if}

{#if !only}
	<div class="filters">
		<label class="search"><Search size={15} aria-hidden="true" /><input type="search" bind:value={q} placeholder={$t('appx.search')} aria-label={$t('appx.search')} /></label>
		<div class="chips" role="group" aria-label={$t('appx.search')}>
			<button class="chip" class:on={!cat} aria-pressed={!cat} onclick={() => (cat = '')}>{$t('appx.cat_all')} <span class="n">{base.length}</span></button>
			{#each cats as c}
				<button class="chip" class:on={cat === c} aria-pressed={cat === c} onclick={() => (cat = cat === c ? '' : c)}>{tx('appx.cat_' + c, c)} <span class="n">{base.filter((x) => x.category === c).length}</span></button>
			{/each}
		</div>
	</div>
{/if}

<div class="grid cards apps">
	{#each shown as c (c.id)}
		<article class="card app" class:off={!c.enabled}>
			<div class="row top">
				<span class="logo" style="--h:{hue(c.id)}" aria-hidden="true">{initials(c.name)}</span>
				<div class="grow">
					<h3>{c.name}</h3>
					<p class="muted small ver">v{c.version}</p>
				</div>
				{#if installedIds.has(c.id)}<span class="badge green">{$t('appx.installed_badge')}</span>{/if}
			</div>
			<p class="desc">{tx('appx.desc_' + c.id, '')}</p>
			<div class="meta">
				{#if c.category}<span class="badge blue">{tx('appx.cat_' + c.category, c.category)}</span>{/if}
				<span class="badge">PHP ≥ {c.min_php || '—'}</span>
				<span class="badge gray" title={$t('appx.license')}>{c.license}</span>
				<span class="badge" title={c.needs_db ? $t('appx.needs_db') : $t('appx.no_db')}>{#if c.needs_db}<Database size={11} aria-hidden="true" /> MySQL{:else}<FileText size={11} aria-hidden="true" /> {$t('appx.no_db')}{/if}</span>
			</div>
			<div class="row foot">
				{#if c.enabled}
					<span class="small muted sum" title={'SHA-256 ' + (c.sha256 || '')}><ShieldCheck size={13} aria-hidden="true" /> {$t('appx.verified')}</span>
					<a class="small" href={c.homepage} target="_blank" rel="noopener noreferrer">{$t('appx.source')}</a>
					<button class="btn primary sm" onclick={() => choose(c)}>{$t('appx.install')}</button>
				{:else}
					<p class="small warn">{$t('appx.disabled')}: {c.disabled_reason}</p>
				{/if}
			</div>
		</article>
	{:else}
		<p class="empty card">{$t('appx.no_match')}</p>
	{/each}
</div>

<section class="card installs">
	<div class="card-head"><h2>{$t('appx.installs_title')}</h2></div>
	<div class="tw">
		<table class="table">
			<thead><tr><th>{$t('appx.app')}</th><th>{$t('appx.url')}</th><th>{$t('appx.database')}</th><th></th></tr></thead>
			<tbody>
				{#each installs.filter((i) => !only || i.app === only) as i}
					<tr><td>{catalog.find((c) => c.id === i.app)?.name ?? i.app} <span class="muted">{i.version}</span></td><td><a href={i.url} target="_blank" rel="noopener noreferrer">{i.url}</a></td><td>{i.db_name || '—'}</td>
						<td class="right"><button class="btn sm" onclick={() => forget(i)}>{$t('appx.forget')}</button></td></tr>
				{:else}
					<tr><td colspan="4" class="muted">{$t('appx.no_installs')}</td></tr>
				{/each}
			</tbody>
		</table>
	</div>
</section>

<style>
	.filters { display: flex; gap: 12px; align-items: center; flex-wrap: wrap; margin-bottom: 14px; }
	.search { position: relative; flex: 0 1 300px; display: flex; align-items: center; }
	.search :global(svg) { position: absolute; left: 10px; color: var(--muted); }
	.search input { padding-left: 32px; }
	.chips { display: flex; gap: 6px; flex-wrap: wrap; }
	.chip { display: inline-flex; align-items: center; gap: 6px; height: 30px; padding: 0 12px; border-radius: 999px; border: 1px solid var(--border-strong); background: var(--card); color: var(--text-2); font: inherit; font-size: 13px; cursor: pointer; }
	.chip:hover { background: var(--card-2); }
	.chip.on { background: var(--primary); border-color: var(--primary); color: var(--primary-text); }
	.chip .n { font-size: 11px; opacity: .75; }
	.apps { margin-bottom: 18px; }
	.app { display: flex; flex-direction: column; gap: 10px; padding: 16px; transition: border-color .15s, box-shadow .15s; }
	.app:hover { border-color: color-mix(in srgb, var(--primary) 40%, var(--border)); }
	.app.off { opacity: .7; }
	.app h3 { margin: 0; font-size: 15px; }
	.app .top { align-items: flex-start; }
	.app .top .grow { min-width: 0; }
	.app .top p { margin: 2px 0 0; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
	.app .top .badge { flex: none; white-space: nowrap; }
	.desc { margin: 0; color: var(--text-2); font-size: 13px; line-height: 1.45; flex: 1; }
	.meta { display: flex; gap: 6px; flex-wrap: wrap; }
	.foot { gap: 10px; border-top: 1px solid var(--border); padding-top: 10px; margin-top: 2px; }
	.foot .sum { display: inline-flex; align-items: center; gap: 4px; flex: 1; }
	.logo { flex: none; display: grid; place-items: center; width: 40px; height: 40px; border-radius: 10px; font-weight: 700; font-size: 14px; color: #fff; background: linear-gradient(135deg, hsl(var(--h) 62% 48%), hsl(calc(var(--h) + 35) 62% 38%)); }
	.installform { margin-bottom: 16px; border-color: color-mix(in srgb, var(--primary) 45%, var(--border)); }
	.installform .fh { margin-bottom: 14px; align-items: flex-start; }
	.installform h2 { margin: 0; }
	.installform .ver { font-weight: 400; }
	.lbl { display: block; font-weight: 600; font-size: 13px; margin-bottom: 5px; }
	.result { align-items: flex-start; }
	.result .rt { margin: 0 0 6px; display: flex; gap: 8px; flex-wrap: wrap; }
	.creds { display: grid; grid-template-columns: max-content 1fr; gap: 2px 14px; margin: 4px 0 8px; font-size: 13px; }
	.creds dt { color: var(--muted); }
	.creds dd { margin: 0; }
	.installs .table td:first-child { white-space: nowrap; }
	@media (max-width: 600px) { .search { flex: 1 1 100%; } }
</style>
