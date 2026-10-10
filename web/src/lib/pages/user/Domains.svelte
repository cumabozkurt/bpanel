<script>
	import { Globe, Plus, ShieldCheck, Network, Pencil, Trash2 } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t } from '$lib/i18n/index.js';
	import { showErr, ok, ask, qs, showWarnings } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';
	import Modal from '$lib/components/Modal.svelte';
	import SortTh from '$lib/components/SortTh.svelte';
	import Pager from '$lib/components/Pager.svelte';
	import { TableState } from '$lib/table.svelte.js';
	import { matches } from '$lib/search.js';
	import { toAsciiDomain, LABEL_PATTERN, typedDomainProblem, domainWasCleaned, relPathProblem, DOCROOT_SEGMENT_MAX } from '$lib/validate.js';
	import { customValidity } from '$lib/a11y.js';

	let list = $state([]);
	let php = $state([]);
	let filter = $state(qs('kind') || '');
	let search = $state('');
	let createOpen = $state(qs('new') === '1');
	let editOpen = $state(false);
	let busy = $state(false);
	let form = $state({ kind: qs('kind') === 'sub' ? 'sub' : qs('kind') === 'alias' ? 'alias' : 'addon', name: '', parent_id: 0, docroot: '', php_version: '' });
	let edit = $state(null);
	const redirectsView = qs('redirects') === '1';

	async function load() {
		try {
			list = await api.get('/user/domains');
			const p = await api.get('/user/php');
			php = p.versions.filter((v) => v.installed);
		} catch (e) { showErr(e); }
	}
	load();

	let parents = $derived(list.filter((d) => d.kind === 'main' || d.kind === 'addon'));
	let shown = $derived(list.filter((d) => (!filter || d.kind === filter) && (!search.trim() || matches(d.name + ' ' + (d.parent_name || '') + ' ' + (d.docroot || ''), search))));
	const tbl = new TableState(() => shown, { key: 'name', get: { kind: (d) => ['main', 'addon', 'sub', 'alias'].indexOf(d.kind) } });
	$effect(() => { search; filter; tbl.reset(); });
	let fullName = $derived(form.kind === 'sub' ? (form.name || '…') + '.' + (parents.find((p) => p.id == form.parent_id)?.name ?? '') : form.name);

	$effect(() => { if (!form.parent_id && parents[0]) form.parent_id = parents[0].id; });

	// R2-UX-11/12: the same domain rules as Create Account, emoji/symbols refused, a stripped scheme or
	// trailing dot shown in the "saved as" line, and the document root checked against /meta.limits.
	let ascii = $derived(form.kind === 'sub' ? '' : toAsciiDomain(form.name));
	let nameProblem = $derived(form.kind !== 'sub' && form.name.trim() ? typedDomainProblem(form.name) : null);
	let autoDocrootTooLong = $derived(form.kind !== 'alias' && !form.docroot.trim() && (form.kind === 'sub' ? (form.name.trim().length + 1 + (parents.find((p) => p.id == form.parent_id)?.name.length ?? 0)) : ascii.length) > DOCROOT_SEGMENT_MAX);
	let docProblem = $derived(form.kind === 'alias' ? null : form.docroot.trim() ? relPathProblem(form.docroot) : autoDocrootTooLong ? 'val.docroot_needed' : null);
	let editDocProblem = $derived(edit && edit.kind !== 'alias' ? relPathProblem(edit.docroot ?? '') : null);

	async function create(e) {
		e.preventDefault();
		if (nameProblem || docProblem) return;
		busy = true;
		try {
			const body = { ...form, docroot: form.docroot.trim().replace(/^\/+|\/+$/g, ''), name: form.kind === 'sub' ? form.name.trim().toLowerCase() : ascii, parent_id: Number(form.parent_id) || 0 };
			if (body.kind === 'addon') body.parent_id = 0;
			const r = await api.post('/user/domains', body);
			ok('domains.created', { name: r.name });
			showWarnings(r);
			createOpen = false;
			form = { ...form, name: '', docroot: '' };
			load();
		} catch (err) { showErr(err); }
		busy = false;
	}
	function openEdit(d) { edit = { id: d.id, name: d.name, kind: d.kind, docroot: d.docroot, php_version: d.php_version, redirect: d.redirect }; editOpen = true; }
	async function save(e) {
		e.preventDefault();
		if (editDocProblem) return;
		busy = true;
		try {
			await api.put('/user/domains/' + edit.id, { docroot: edit.docroot, php_version: edit.php_version, redirect: edit.redirect });
			ok('common.saved');
			editOpen = false;
			load();
		} catch (err) { showErr(err); }
		busy = false;
	}
	async function del(d) {
		if (!ask('domains.confirm_delete', { name: d.name })) return;
		try { const r = await api.del('/user/domains/' + d.id); ok('domains.deleted', { name: d.name }); showWarnings(r); load(); } catch (err) { showErr(err); }
	}
	const kindColor = { main: 'teal', addon: 'blue', sub: '', alias: 'amber' };
</script>

<PageHead title={redirectsView ? $t('tools.redirects') : $t('domains.title')} desc={redirectsView ? $t('domains.redirects_desc') : $t('domains.desc')} icon={Globe}>
	{#snippet actions()}<button class="btn primary" onclick={() => (createOpen = true)}><Plus size={16} /> {$t('domains.create')}</button>{/snippet}
</PageHead>

<div class="card">
	<div class="toolbar">
		<input type="search" placeholder={$t('common.search')} bind:value={search} aria-label={$t('common.search')} />
		<select bind:value={filter} style="width:auto" aria-label={$t('domains.type')}>
			<option value="">{$t('domains.all_types')}</option>
			{#each ['main', 'addon', 'sub', 'alias'] as k}<option value={k}>{$t('domains.kind_' + k)}</option>{/each}
		</select>
		<span class="grow"></span>
		<span class="muted small">{$t('common.count', { n: shown.length })}</span>
	</div>
	<div class="tw">
	<table class="table">
		<thead><tr><SortTh {tbl} key="name" label={$t('domains.domain')} /><SortTh {tbl} key="kind" label={$t('domains.type')} /><SortTh {tbl} key="docroot" label={$t('domains.docroot')} /><SortTh {tbl} key="php_version" label="PHP" /><th>{$t('domains.redirect')}</th><SortTh {tbl} key="ssl_status" label="SSL" /><th><span class="sr-only">{$t('common.actions')}</span></th></tr></thead>
		<tbody>
			{#each tbl.page as d}
				<tr>
					<td><a href={'http://' + d.name} target="_blank" rel="noopener">{d.name}</a>{#if d.parent_name}<div class="muted small">→ {d.parent_name}</div>{/if}</td>
					<td><span class="badge {kindColor[d.kind]}">{$t('domains.kind_' + d.kind)}</span></td>
					<td class="mono">{d.kind === 'alias' ? '—' : '~/' + d.docroot}</td>
					<td>{d.kind === 'alias' ? '—' : d.php_version || $t('domains.inherit')}</td>
					<td class="small">{d.redirect || '—'}</td>
					<td>{#if d.ssl_status === 'active'}<span class="badge green"><ShieldCheck size={11} /> {$t('ssl.active')}</span>{:else if d.kind !== 'alias'}<span class="badge">{$t('ssl.none')}</span>{/if}</td>
					<td>
						<div class="actions">
							{#if d.kind !== 'alias'}<button class="linkbtn" onclick={() => openEdit(d)} aria-label={$t('domains.manage_named', { name: d.name })}><Pencil size={13} /> {$t('common.manage')}</button>{/if}
							{#if d.kind !== 'sub'}<a href={'/dns/' + d.name} aria-label={$t('domains.dns_named', { name: d.name })}><Network size={13} /> DNS</a>{/if}
							{#if d.kind !== 'main'}<button class="linkbtn danger" onclick={() => del(d)} aria-label={$t('domains.delete_named', { name: d.name })}><Trash2 size={13} /> {$t('common.delete')}</button>{/if}
						</div>
					</td>
				</tr>
			{:else}
				<tr><td colspan="7" class="empty">{$t('common.none')}</td></tr>
			{/each}
		</tbody>
	</table>
	</div>
	<Pager {tbl} />
</div>

<Modal bind:open={createOpen} title={$t('domains.create')}>
	<form id="dcreate" onsubmit={create}>
		<label class="field"><span>{$t('domains.type')}</span>
			<select bind:value={form.kind}>
				<option value="addon">{$t('domains.kind_addon')}</option>
				<option value="sub">{$t('domains.kind_sub')}</option>
				<option value="alias">{$t('domains.kind_alias')}</option>
			</select>
			<small>{$t('domains.kind_help_' + form.kind)}</small>
		</label>
		{#if form.kind === 'sub'}
			<label class="field"><span>{$t('domains.subdomain')}</span>
				<div class="input-group"><input bind:value={form.name} placeholder="blog" required pattern={LABEL_PATTERN + '(\\.' + LABEL_PATTERN + ')*'} data-err="errors.invalid_label" autocapitalize="off" spellcheck="false" /><select bind:value={form.parent_id} style="width:auto;border-radius:0 6px 6px 0" aria-label={$t('domains.parent')}>{#each parents as p}<option value={p.id}>.{p.name}</option>{/each}</select></div>
			</label>
		{:else}
			<label class="field"><span>{$t('domains.domain')}</span><input id="dom-name" bind:value={form.name} placeholder="example.com" required autocapitalize="off" spellcheck="false" use:customValidity={nameProblem} aria-invalid={nameProblem ? 'true' : undefined} />
				{#if nameProblem}<small class="field-err">{$t(nameProblem)}</small>
				{:else if form.name && (ascii !== form.name.trim().toLowerCase() || domainWasCleaned(form.name))}<small>{$t('domains.idn_note', { ascii })}</small>{/if}</label>
			{#if form.kind === 'alias'}
				<label class="field"><span>{$t('domains.alias_target')}</span><select bind:value={form.parent_id}>{#each parents as p}<option value={p.id}>{p.name}</option>{/each}</select></label>
			{/if}
		{/if}
		{#if form.kind !== 'alias'}
			<label class="field"><span>{$t('domains.docroot')}</span>
				<div class="input-group"><span class="addon">~/</span><input id="dom-docroot" bind:value={form.docroot} placeholder={fullName} use:customValidity={docProblem} aria-invalid={docProblem ? 'true' : undefined} autocapitalize="off" spellcheck="false" /></div>
				{#if docProblem}<small class="field-err">{$t(docProblem)}</small>{:else}<small>{$t('domains.docroot_help')}</small>{/if}
			</label>
			<label class="field"><span>{$t('domains.php_version')}</span>
				<select bind:value={form.php_version}><option value="">{$t('domains.inherit')}</option>{#each php as v}<option value={v.version}>PHP {v.version}</option>{/each}</select>
			</label>
		{/if}
	</form>
	{#snippet footer()}<button class="btn" onclick={() => (createOpen = false)}>{$t('common.cancel')}</button><button class="btn primary" form="dcreate" disabled={busy}>{$t('common.create')}</button>{/snippet}
</Modal>

<Modal bind:open={editOpen} title={edit?.name ?? ''}>
	{#if edit}
		<form id="dedit" onsubmit={save}>
			<label class="field"><span>{$t('domains.docroot')}</span><div class="input-group"><span class="addon">~/</span><input bind:value={edit.docroot} required use:customValidity={editDocProblem} aria-invalid={editDocProblem ? 'true' : undefined} autocapitalize="off" spellcheck="false" /></div>
				{#if editDocProblem}<small class="field-err">{$t(editDocProblem)}</small>{:else}<small>{$t('errors.invalid_docroot_hint')}</small>{/if}</label>
			<label class="field"><span>{$t('domains.php_version')}</span>
				<select bind:value={edit.php_version}><option value="">{$t('domains.inherit')}</option>{#each php as v}<option value={v.version}>PHP {v.version}</option>{/each}</select>
			</label>
			<label class="field"><span>{$t('domains.redirect')}</span><input type="url" bind:value={edit.redirect} placeholder="https://www.example.com" pattern="https?://.+" data-err="errors.invalid_redirect" /><small>{$t('domains.redirect_help')}</small></label>
		</form>
	{/if}
	{#snippet footer()}<button class="btn" onclick={() => (editOpen = false)}>{$t('common.cancel')}</button><button class="btn primary" form="dedit" disabled={busy}>{$t('common.save')}</button>{/snippet}
</Modal>
