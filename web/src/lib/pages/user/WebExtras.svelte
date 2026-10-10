<script>
	// v0.4 webx: Directory Privacy, Hotlink Protection, Error Pages, MIME Types and IP Blocker.
	// One page, one section per route (/web/:section); every save replaces that section of the
	// selected domain and is applied by the agent with a web server config test + rollback.
	import { Lock, Image, FileWarning, FileText, Ban, Plus, Trash2, Save, FolderTree, Cog, ShieldAlert, RefreshCw } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t } from '$lib/i18n/index.js';
	import { showErr, ok, ask } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';
	let { params } = $props();
	const SECTIONS = {
		privacy: { tool: 'directory_privacy', icon: Lock },
		hotlink: { tool: 'hotlink', icon: Image },
		'error-pages': { tool: 'error_pages', icon: FileWarning },
		mime: { tool: 'mime_types', icon: FileText },
		'ip-blocker': { tool: 'ip_blocker', icon: Ban },
		indexes: { tool: 'directory_indexes', icon: FolderTree }, // v1.1
		handlers: { tool: 'apache_handlers', icon: Cog }, // v1.1
		leech: { tool: 'leech_protection', icon: ShieldAlert } // v1.1
	};
	let section = $derived(SECTIONS[params.section] ? params.section : 'privacy');
	let meta = $derived(SECTIONS[section]);
	let domains = $state([]);
	let sel = $state(null);
	let cur = $derived(domains.find((d) => d.id === sel) ?? null);
	let busy = $state(false);

	// editable copies of the selected domain's settings
	let dirs = $state([]);
	let hot = $state({ enabled: false, allowed: '', exts: 'jpg jpeg png gif webp svg', allow_empty: true });
	let pages = $state({});
	let pageCode = $state('404');
	let mime = $state([]);
	let deny = $state('');
	let indexes = $state([]);
	let handlers = $state([]);
	let leech = $state([]);

	function fill(d) {
		if (!d) return;
		dirs = d.privacy.map((p) => ({ path: p.path, realm: p.realm, users: p.users.map((u) => ({ name: u, password: '', keep: true })) }));
		hot = { enabled: d.hotlink.enabled, allowed: d.hotlink.allowed.join('\n'), exts: d.hotlink.exts.length ? d.hotlink.exts.join(' ') : 'jpg jpeg png gif webp svg', allow_empty: d.hotlink.enabled ? d.hotlink.allow_empty : true };
		pages = { ...d.error_pages };
		mime = d.mime.map((m) => ({ ...m }));
		deny = d.deny.join('\n');
		indexes = (d.indexes ?? []).map((x) => ({ ...x }));
		handlers = (d.handlers ?? []).map((x) => ({ ...x }));
		leech = d.privacy.map((p) => ({ path: p.path, leech_max: p.leech_max ?? 0, disabled: p.disabled ?? [] }));
	}
	async function load() {
		try {
			domains = (await api.get('/user/web/extras')).domains ?? [];
			if (!domains.find((d) => d.id === sel)) sel = domains[0]?.id ?? null;
			fill(domains.find((d) => d.id === sel));
		} catch (e) { showErr(e); }
	}
	load();
	function pick(e) { sel = Number(e.currentTarget.value); fill(cur); }
	const words = (s) => s.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);

	async function save(path, body) {
		if (!cur) return;
		busy = true;
		try {
			const r = await api.put(`/user/web/${cur.id}/${path}`, body);
			domains = domains.map((d) => (d.id === r.id ? r : d));
			fill(r);
			ok('webx.applied');
		} catch (e) { showErr(e); }
		busy = false;
	}
	const savePrivacy = (e) => { e?.preventDefault(); save('privacy', { dirs: dirs.map((d) => ({ path: d.path, realm: d.realm, users: d.users.map((u) => (u.password ? { name: u.name, password: u.password } : { name: u.name })) })) }); };
	const saveHotlink = (e) => { e.preventDefault(); save('hotlink', { enabled: hot.enabled, allowed: words(hot.allowed), exts: words(hot.exts), allow_empty: hot.allow_empty }); };
	const savePages = (e) => { e.preventDefault(); save('error-pages', { pages: Object.fromEntries(Object.entries(pages).filter(([, v]) => v && v.trim())) }); };
	const saveMime = (e) => { e.preventDefault(); save('mime', { types: mime.filter((m) => m.ext || m.type) }); };
	const saveDeny = (e) => { e.preventDefault(); save('ip-blocker', { deny: words(deny) }); };
	const saveIndexes = (e) => { e.preventDefault(); save('indexes', { indexes: indexes.filter((x) => x.path) }); };
	const saveHandlers = (e) => { e.preventDefault(); save('handlers', { handlers: handlers.filter((x) => x.ext) }); };
	const saveLeech = (l) => save('leech', { path: l.path, leech_max: Number(l.leech_max) || 0 });
	async function leechPost(path, body, msg) {
		if (!cur) return;
		busy = true;
		try {
			const r = await api.post(`/user/web/${cur.id}/${path}`, body);
			if (r?.id) { domains = domains.map((d) => (d.id === r.id ? r : d)); fill(r); }
			ok(msg, { n: r?.disabled_now ?? 0 });
		} catch (e) { showErr(e); }
		busy = false;
	}
	function removeDir(i) { if (!ask('webx.privacy_confirm_remove', { path: dirs[i].path })) return; dirs = dirs.filter((_, j) => j !== i); savePrivacy(); }
	const sample = (c) => `<!doctype html>\n<html><head><meta charset="utf-8"><title>${c}</title></head>\n<body><h1>${c}</h1><p></p></body></html>\n`;
</script>

<PageHead title={$t('tools.' + meta.tool)} desc={$t('webx.' + meta.tool + '_desc')} icon={meta.icon} />
<div class="stack">
	<div class="card"><div class="card-body row wraprow">
		<label class="field" style="max-width:360px"><span>{$t('webx.domain')}</span>
			<select onchange={pick} value={sel} disabled={!domains.length}>{#each domains as d}<option value={d.id}>{d.domain}</option>{/each}</select></label>
		{#if !domains.length}<span class="muted small">{$t('webx.no_domains')}</span>{/if}
		<span class="muted small">{$t('webx.applied_help')}</span>
	</div></div>

	{#if cur}
		{#if section === 'privacy'}
			<form class="card" onsubmit={savePrivacy}>
				<div class="card-head"><Lock size={17} /><h2>{$t('webx.privacy_dirs')}</h2></div>
				<div class="card-body stack">
					<p class="muted small">{$t('webx.privacy_help')}</p>
					{#each dirs as d, i}
						<fieldset class="box">
							<div class="row wraprow">
								<label class="field"><span>{$t('webx.path')}</span><input class="mono" bind:value={d.path} placeholder="/private/" required maxlength="255" autocapitalize="off" spellcheck="false" /></label>
								<label class="field"><span>{$t('webx.realm')}</span><input bind:value={d.realm} placeholder="Restricted" maxlength="64" /></label>
								<button type="button" class="linkbtn danger" onclick={() => removeDir(i)}><Trash2 size={13} /> {$t('common.delete')}</button>
							</div>
							{#each d.users as u, k}
								<div class="row wraprow">
									<label class="field"><span>{$t('webx.user')}</span><input class="mono" bind:value={u.name} required maxlength="32" autocapitalize="off" spellcheck="false" autocomplete="off" /></label>
									<label class="field"><span>{$t('webx.password')}</span><input type="password" bind:value={u.password} minlength={u.keep ? undefined : 8} maxlength="72" required={!u.keep} autocomplete="new-password" placeholder={u.keep ? $t('webx.password_keep') : ''} /></label>
									<button type="button" class="linkbtn danger" onclick={() => (d.users = d.users.filter((_, j) => j !== k))} aria-label={$t('webx.remove_user', { name: u.name })}><Trash2 size={13} /></button>
								</div>
							{/each}
							<button type="button" class="linkbtn" onclick={() => d.users.push({ name: '', password: '', keep: false })}><Plus size={13} /> {$t('webx.add_user')}</button>
						</fieldset>
					{:else}<p class="empty">{$t('webx.privacy_none')}</p>{/each}
					<div class="row"><button type="button" class="btn" onclick={() => dirs.push({ path: '', realm: '', users: [{ name: '', password: '', keep: false }] })}><Plus size={14} /> {$t('webx.add_dir')}</button>
						<button class="btn primary" disabled={busy}><Save size={14} /> {$t('common.save')}</button></div>
				</div>
			</form>
		{:else if section === 'hotlink'}
			<form class="card" onsubmit={saveHotlink}>
				<div class="card-head"><Image size={17} /><h2>{$t('tools.hotlink')}</h2></div>
				<div class="card-body stack">
					<label class="check"><input type="checkbox" bind:checked={hot.enabled} /> {$t('webx.hotlink_enable')}</label>
					<label class="field"><span>{$t('webx.hotlink_allowed')}</span><textarea class="mono" rows="3" bind:value={hot.allowed} placeholder="partner.example"></textarea><small>{$t('webx.hotlink_allowed_help', { domain: cur.domain })}</small></label>
					<label class="field"><span>{$t('webx.hotlink_exts')}</span><input class="mono" bind:value={hot.exts} /><small>{$t('webx.hotlink_exts_help')}</small></label>
					<label class="check"><input type="checkbox" bind:checked={hot.allow_empty} /> {$t('webx.hotlink_allow_empty')}</label>
					<div><button class="btn primary" disabled={busy}><Save size={14} /> {$t('common.save')}</button></div>
				</div>
			</form>
		{:else if section === 'error-pages'}
			<form class="card" onsubmit={savePages}>
				<div class="card-head"><FileWarning size={17} /><h2>{$t('tools.error_pages')}</h2></div>
				<div class="card-body stack">
					<div class="row wraprow" role="tablist" aria-label={$t('webx.status_code')}>
						{#each cur.error_codes as c}<button type="button" role="tab" aria-selected={pageCode === String(c)} class="btn" class:primary={pageCode === String(c)} onclick={() => (pageCode = String(c))}>{c}{pages[c] ? ' •' : ''}</button>{/each}
					</div>
					<label class="field"><span>{$t('webx.page_html', { code: pageCode })}</span><textarea class="mono" rows="12" bind:value={pages[pageCode]} maxlength="65536" spellcheck="false"></textarea>
						<small>{$t('webx.page_help')}</small></label>
					<div class="row"><button type="button" class="btn" onclick={() => (pages[pageCode] = sample(pageCode))}>{$t('webx.page_sample')}</button>
						<button type="button" class="btn" onclick={() => (pages[pageCode] = '')}>{$t('webx.page_clear')}</button>
						<button class="btn primary" disabled={busy}><Save size={14} /> {$t('common.save')}</button></div>
				</div>
			</form>
		{:else if section === 'mime'}
			<form class="card" onsubmit={saveMime}>
				<div class="card-head"><FileText size={17} /><h2>{$t('tools.mime_types')}</h2></div>
				<div class="card-body stack">
					<p class="muted small">{$t('webx.mime_help')}</p>
					{#each mime as m, i}
						<div class="row wraprow">
							<label class="field"><span>{$t('webx.mime_ext')}</span><input class="mono" bind:value={m.ext} placeholder="webmanifest" maxlength="16" required autocapitalize="off" /></label>
							<label class="field"><span>{$t('webx.mime_type')}</span><input class="mono" bind:value={m.type} placeholder="application/manifest+json" maxlength="120" required autocapitalize="off" /></label>
							<button type="button" class="linkbtn danger" onclick={() => (mime = mime.filter((_, j) => j !== i))}><Trash2 size={13} /> {$t('common.delete')}</button>
						</div>
					{:else}<p class="empty">{$t('common.none')}</p>{/each}
					<div class="row"><button type="button" class="btn" onclick={() => mime.push({ ext: '', type: '' })}><Plus size={14} /> {$t('webx.mime_add')}</button>
						<button class="btn primary" disabled={busy}><Save size={14} /> {$t('common.save')}</button></div>
				</div>
			</form>
		{:else if section === 'indexes'}
			<form class="card" onsubmit={saveIndexes}>
				<div class="card-head"><FolderTree size={17} /><h2>{$t('tools.directory_indexes')}</h2></div>
				<div class="card-body stack">
					<p class="muted small">{$t('v11.indexes_help')}</p>
					{#each indexes as x, i}
						<div class="row wraprow">
							<label class="field"><span>{$t('webx.path')}</span><input class="mono" bind:value={x.path} placeholder="/downloads/" required maxlength="255" autocapitalize="off" spellcheck="false" /></label>
							<label class="field"><span>{$t('v11.listing')}</span><select bind:value={x.mode}><option value="on">{$t('v11.listing_on')}</option><option value="off">{$t('v11.listing_off')}</option></select></label>
							<button type="button" class="linkbtn danger" onclick={() => (indexes = indexes.filter((_, j) => j !== i))}><Trash2 size={13} /> {$t('common.delete')}</button>
						</div>
					{:else}<p class="empty">{$t('v11.indexes_none')}</p>{/each}
					<div class="row"><button type="button" class="btn" onclick={() => indexes.push({ path: '/', mode: 'off' })}><Plus size={14} /> {$t('v11.add_dir')}</button>
						<button class="btn primary" disabled={busy}><Save size={14} /> {$t('common.save')}</button></div>
				</div>
			</form>
		{:else if section === 'handlers'}
			<form class="card" onsubmit={saveHandlers}>
				<div class="card-head"><Cog size={17} /><h2>{$t('tools.apache_handlers')}</h2></div>
				<div class="card-body stack">
					<p class="muted small">{$t('v11.handlers_help')}</p>
					{#each handlers as x, i}
						<div class="row wraprow">
							<label class="field"><span>{$t('webx.mime_ext')}</span><input class="mono" bind:value={x.ext} placeholder="shtml" required maxlength="16" autocapitalize="off" /></label>
							<label class="field"><span>{$t('v11.handler')}</span><select bind:value={x.handler}>{#each cur.handler_names ?? ['default-handler', 'text-plain', 'server-parsed'] as h}<option value={h}>{$t('v11.handler_' + h.replace('-', '_'))}</option>{/each}</select></label>
							<button type="button" class="linkbtn danger" onclick={() => (handlers = handlers.filter((_, j) => j !== i))}><Trash2 size={13} /> {$t('common.delete')}</button>
						</div>
					{:else}<p class="empty">{$t('common.none')}</p>{/each}
					<div class="row"><button type="button" class="btn" onclick={() => handlers.push({ ext: '', handler: 'server-parsed' })}><Plus size={14} /> {$t('v11.add_handler')}</button>
						<button class="btn primary" disabled={busy}><Save size={14} /> {$t('common.save')}</button></div>
				</div>
			</form>
		{:else if section === 'leech'}
			<div class="card">
				<div class="card-head"><ShieldAlert size={17} /><h2>{$t('tools.leech_protection')}</h2></div>
				<div class="card-body stack">
					<p class="muted small">{$t('v11.leech_help', { hours: Math.round((cur.leech_window ?? 7200) / 3600) })}</p>
					{#each leech as l}
						<fieldset class="box">
							<div class="row wraprow">
								<strong class="mono">{l.path}</strong>
								<label class="field"><span>{$t('v11.leech_max')}</span><input type="number" min="0" max="1000" bind:value={l.leech_max} /></label>
								<button type="button" class="btn primary" disabled={busy} onclick={() => saveLeech(l)}><Save size={14} /> {$t('common.save')}</button>
							</div>
							{#each l.disabled as u}
								<div class="row"><span class="badge amber">{$t('v11.leech_disabled')}</span> <span class="mono">{u}</span>
									<button type="button" class="linkbtn" disabled={busy} onclick={() => leechPost('leech/enable', { path: l.path, user: u }, 'v11.leech_enabled')}>{$t('v11.leech_enable')}</button></div>
							{/each}
						</fieldset>
					{:else}<p class="empty">{$t('v11.leech_none')}</p>{/each}
					{#if leech.length}<div><button type="button" class="btn" disabled={busy} onclick={() => leechPost('leech/scan', {}, 'v11.leech_scanned')}><RefreshCw size={14} /> {$t('v11.leech_scan')}</button></div>{/if}
				</div>
			</div>
		{:else}
			<form class="card" onsubmit={saveDeny}>
				<div class="card-head"><Ban size={17} /><h2>{$t('tools.ip_blocker')}</h2></div>
				<div class="card-body stack">
					<label class="field"><span>{$t('webx.deny_list')}</span><textarea class="mono" rows="8" bind:value={deny} placeholder={'192.0.2.10\n198.51.100.0/24\n2001:db8::/32'} spellcheck="false"></textarea>
						<small>{$t('webx.deny_help')}</small></label>
					<div><button class="btn primary" disabled={busy}><Save size={14} /> {$t('common.save')}</button></div>
				</div>
			</form>
		{/if}
	{/if}
</div>

<style>
	.wraprow { flex-wrap: wrap; align-items: flex-end; }
	.box { border: 1px solid var(--border); border-radius: 8px; padding: 10px 12px; display: grid; gap: 8px; }
	.check { display: flex; gap: 8px; align-items: center; }
</style>
