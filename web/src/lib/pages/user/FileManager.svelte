<script>
	import {
		Folder, FileText, FilePlus, FolderPlus, Upload, Download, Trash2, Pencil, Copy, MoveRight, Lock, Archive,
		PackageOpen, RefreshCw, Home, ArrowUp, FileCode, FileImage, FileArchive, File, Link
	} from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t, fmt } from '$lib/i18n/index.js';
	import { showErr, ok, ask } from '$lib/util.js';
	import Modal from '$lib/components/Modal.svelte';
	import SortTh from '$lib/components/SortTh.svelte';
	import { TableState } from '$lib/table.svelte.js';
	import { page } from '$app/state';
	import { replaceState } from '$app/navigation';
	import { untrack } from 'svelte';
	import { serverLimits, fileNameProblem } from '$lib/validate.js';
	import { customValidity } from '$lib/a11y.js';
	import { pageTitle } from '$lib/stores.js';
	$effect(() => { pageTitle.set($t('tools.file_manager')); return () => pageTitle.set(''); });

	let cwd = $state(new URLSearchParams(location.search).get('path') ?? 'public_html');
	let pathInput = $state('');
	let entries = $state([]);
	let sel = $state([]);
	let loading = $state(false);
	let tops = $state([]);
	let dialog = $state(null); // {kind, ...}
	let dlgOpen = $state(false);
	let editor = $state(null);
	let edOpen = $state(false);
	let files = $state(null);
	let busy = $state(false);
	let uploadError = $state(false);
	let cursor = $state(-1); // keyboard cursor row index in the sorted list
	let listEl = $state();
	// Long folders (perf): render the first CHUNK rows, then more as the list scrolls into view
	// (or when the keyboard cursor moves past them), so a 10 000-file folder stays responsive.
	const CHUNK = 300;
	let shownRows = $state(CHUNK);
	let moreEl = $state();
	$effect(() => {
		if (!moreEl || typeof IntersectionObserver === 'undefined') return;
		const io = new IntersectionObserver((es) => { if (es.some((x) => x.isIntersecting)) shownRows += CHUNK; });
		io.observe(moreEl);
		return () => io.disconnect();
	});
	const tbl = new TableState(() => entries, { key: 'name', paged: false, pin: (e) => (e.is_dir ? 0 : 1), get: { size: (e) => (e.is_dir ? -1 : e.size), mod: (e) => e.mod_unix, perm: (e) => e.perm } });
	let dirty = $derived(!!editor && editor.content !== editor.original);

	const join = (a, b) => (a ? a + '/' + b : b);
	async function load(p = cwd) {
		loading = true;
		try {
			const r = await api.post('/user/files', { op: 'list', path: p });
			// R2-UX-35: the panel's own account marker is not a user file
			entries = (r.entries ?? []).filter((e) => !(p === '' && e.name === '.bpanel'));
			cwd = p;
			shownRows = CHUNK;
			pathInput = '/' + p;
			sel = [];
			cursor = -1;
			const url = '/files?path=' + encodeURIComponent(p);
			if (location.pathname + location.search !== url) { try { replaceState(url, {}); } catch { history.replaceState(history.state, '', url); } lastHref = location.href; }
		} catch (e) { showErr(e); }
		loading = false;
	}
	async function loadTops() {
		try { tops = ((await api.post('/user/files', { op: 'list', path: '' })).entries ?? []).filter((e) => e.is_dir); } catch {}
	}
	load();
	loadTops();
	// a link to /files?path=… while already on the File Manager (e.g. from the search) opens that folder
	let lastHref = typeof location !== 'undefined' ? location.href : '';
	$effect(() => {
		const href = page.url.href;
		if (href === lastHref) return;
		lastHref = href;
		const want = page.url.searchParams.get('path');
		untrack(() => { if (want !== null && want !== cwd) load(want); });
	});

	let crumbs = $derived(cwd ? cwd.split('/') : []);
	let selected = $derived(entries.filter((e) => sel.includes(e.name)));
	let one = $derived(selected.length === 1 ? selected[0] : null);

	function icon(e) {
		if (e.is_dir) return Folder;
		if (e.is_link) return Link;
		const x = e.name.split('.').pop().toLowerCase();
		if (['php', 'js', 'css', 'html', 'htm', 'json', 'py', 'sh', 'ts', 'xml', 'yml', 'yaml', 'htaccess'].includes(x) || e.name.startsWith('.')) return FileCode;
		if (['png', 'jpg', 'jpeg', 'gif', 'svg', 'webp', 'ico', 'avif'].includes(x)) return FileImage;
		if (['zip', 'gz', 'tgz', 'tar', 'bz2', 'xz', '7z'].includes(x)) return FileArchive;
		if (['txt', 'md', 'log', 'csv', 'ini', 'conf'].includes(x)) return FileText;
		return File;
	}
	function toggle(name, ev) {
		const idx = tbl.sorted.findIndex((x) => x.name === name);
		if (ev?.shiftKey && cursor >= 0) {
			const [a, b] = [Math.min(cursor, idx), Math.max(cursor, idx)];
			sel = tbl.sorted.slice(a, b + 1).map((x) => x.name);
		} else if (ev?.ctrlKey || ev?.metaKey || ev?.target?.type === 'checkbox') sel = sel.includes(name) ? sel.filter((x) => x !== name) : [...sel, name];
		else sel = [name];
		cursor = idx;
	}
	function open(e) {
		if (e.is_dir) load(join(cwd, e.name));
		else edit(e);
	}
	function up() { load(cwd.split('/').slice(0, -1).join('/')); }
	// R2-UX-21: trim pasted spaces; a path that tries to leave the home directory is refused with a note
	let pathNote = $state('');
	function go(ev) {
		ev.preventDefault();
		const raw = pathInput.trim();
		const parts = raw.replace(/^~\/?/, '').split('/').filter((x) => x && x !== '.');
		let depth = 0;
		for (const x of parts) { depth += x === '..' ? -1 : 1; if (depth < 0) break; }
		if (depth < 0 || parts.includes('..')) { pathNote = 'fm.path_outside_home'; pathInput = '/' + cwd; return; }
		pathNote = raw !== pathInput ? 'fm.path_trimmed' : '';
		load(parts.join('/'));
	}
	// R2-UX-16: names are one path segment, never . or .., at most 255 bytes; spaces are trimmed
	let nameProblem = $derived(dialog && ['file', 'folder', 'rename', 'zip'].includes(dialog.kind) ? fileNameProblem(dialog.value) : null);
	let nameTrimmed = $derived(dialog && ['file', 'folder', 'rename', 'zip'].includes(dialog.kind) && dialog.value !== dialog.value.trim() && !!dialog.value.trim());

	async function op(body, msgKey) {
		busy = true;
		try { await api.post('/user/files', body); if (msgKey) ok(msgKey); dlgOpen = false; await load(); loadTops(); }
		catch (e) { showErr(e); }
		busy = false;
	}
	function dlg(kind, extra = {}) { dialog = { kind, value: '', ...extra }; if (kind === 'upload') { files = null; uploadError = false; } dlgOpen = true; }
	async function submitDlg(ev) {
		ev.preventDefault();
		const d = dialog;
		if (nameProblem) return;
		if (['file', 'folder', 'rename', 'zip'].includes(d.kind)) d.value = d.value.trim();
		switch (d.kind) {
			case 'file': return op({ op: 'touch', path: join(cwd, d.value) }, 'fm.created');
			case 'folder': return op({ op: 'mkdir', path: join(cwd, d.value) }, 'fm.created');
			case 'rename': return op({ op: 'rename', path: join(cwd, one.name), dest: join(cwd, d.value) }, 'fm.renamed');
			case 'move': return op({ op: 'move', path: join(cwd, one.name), dest: d.value.replace(/^\/+/, '') }, 'fm.moved');
			case 'copy': return op({ op: 'copy', path: join(cwd, one.name), dest: d.value.replace(/^\/+/, '') }, 'fm.copied');
			case 'zip': return op({ op: 'zip', paths: selected.map((e) => join(cwd, e.name)), dest: join(cwd, d.value.endsWith('.zip') ? d.value : d.value + '.zip') }, 'fm.compressed');
			case 'unzip': return op({ op: 'unzip', path: join(cwd, one.name), dest: d.value.replace(/^\/+/, '') }, 'fm.extracted');
			case 'chmod': return op({ op: 'chmod', paths: selected.map((e) => join(cwd, e.name)), mode: parseInt(d.value, 8) }, 'fm.perms_changed');
			case 'upload': return upload();
		}
	}
	async function del() {
		if (!selected.length || !ask('fm.confirm_delete', { n: selected.length })) return;
		op({ op: 'delete', paths: selected.map((e) => join(cwd, e.name)) }, 'fm.deleted');
	}
	async function edit(e) {
		try {
			const r = await api.post('/user/files', { op: 'read', path: join(cwd, e.name) });
			editor = { name: e.name, path: join(cwd, e.name), content: r.content, original: r.content };
			edOpen = true;
		} catch (err) { showErr(err); }
	}
	async function saveEdit() {
		busy = true;
		try { await api.post('/user/files', { op: 'write', path: editor.path, content: editor.content }); ok('fm.saved', { name: editor.name }); editor.original = editor.content; load(); setTimeout(() => document.querySelector('textarea.code')?.focus(), 0); }
		catch (err) { showErr(err); }
		busy = false;
	}
	// unsaved-changes guard for the editor (close button, Esc, backdrop, leaving the page)
	function canCloseEditor() {
		if (!dirty) return true;
		return window.confirm($t('fm.unsaved_confirm', { name: editor.name }));
	}
	function closeEditor() { if (canCloseEditor()) edOpen = false; }
	function edKey(e) {
		if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 's') { e.preventDefault(); if (!busy) saveEdit(); }
	}
	function beforeUnload(e) { if (edOpen && dirty) { e.preventDefault(); e.returnValue = ''; } }
	async function upload() {
		if (!files?.length) { uploadError = true; document.getElementById('fm-upload')?.focus(); return; }
		const big = serverLimits.uploadMaxFile ? [...files].find((f) => f.size > serverLimits.uploadMaxFile) : null;
		if (big) { uploadError = { key: 'fm.upload_too_big', params: { name: big.name, max: $fmt.bytes(serverLimits.uploadMaxFile) } }; return; }
		const total = [...files].reduce((n, f) => n + f.size, 0);
		if (serverLimits.uploadMaxRequest && total > serverLimits.uploadMaxRequest) { uploadError = { key: 'fm.upload_total_too_big', params: { max: $fmt.bytes(serverLimits.uploadMaxRequest) } }; return; }
		uploadError = false;
		busy = true;
		const fd = new FormData();
		fd.append('path', cwd);
		for (const f of files) fd.append('file', f);
		try { const r = await api.post('/user/files/upload', fd); ok('fm.uploaded', { n: r.uploaded.length }); dlgOpen = false; files = null; load(); }
		catch (err) { showErr(err); }
		busy = false;
	}
	function download() {
		for (const e of selected.filter((x) => !x.is_dir)) {
			const a = document.createElement('a');
			a.href = '/api/v1/user/files/download?path=' + encodeURIComponent(join(cwd, e.name));
			a.download = e.name;
			a.click();
		}
	}
	// permissions helpers
	const bits = [['owner', 6], ['group', 3], ['world', 0]];
	function bit(mode, shift, b) { return ((parseInt(mode || '0', 8) >> shift) & b) !== 0; }
	function setBit(shift, b, on) {
		let m = parseInt(dialog.value || '0', 8);
		m = on ? m | (b << shift) : m & ~(b << shift);
		dialog.value = m.toString(8).padStart(3, '0');
	}
	// Keyboard shortcuts, active while focus is in the file list (or nowhere in particular):
	// ↑/↓ move, Shift+↑/↓ extend, Space toggle, Enter open, Backspace/Alt+↑ parent folder,
	// Delete delete, F2 rename, Ctrl+A select all, Esc clear selection, Home/End first/last.
	function moveCursor(i, extend) {
		const list = tbl.sorted;
		if (!list.length) return;
		const n = Math.max(0, Math.min(list.length - 1, i));
		if (n >= shownRows) shownRows = n + CHUNK;
		if (extend && cursor >= 0) {
			const name = list[n].name;
			sel = sel.includes(name) ? sel : [...sel, name];
		} else sel = [list[n].name];
		cursor = n;
		listEl?.querySelector(`tr[data-i="${n}"]`)?.scrollIntoView({ block: 'nearest' });
	}
	function keydown(ev) {
		if (dlgOpen || edOpen || document.querySelector('[role=dialog]')) return;
		const tag = (ev.target.tagName || '').toLowerCase();
		if (tag === 'input' || tag === 'textarea' || tag === 'select' || ev.target.isContentEditable) return;
		const inList = listEl?.contains(ev.target);
		const neutral = ev.target === document.body || ev.target.id === 'main-content';
		if (!inList && !neutral) return; // don't hijack keys on toolbar buttons, links, the sidebar…
		const k = ev.key;
		const handled = () => ev.preventDefault();
		if (k === 'ArrowDown') { handled(); moveCursor(cursor + 1, ev.shiftKey); }
		else if (k === 'ArrowUp' && ev.altKey) { handled(); if (cwd) up(); }
		else if (k === 'ArrowUp') { handled(); moveCursor(cursor < 0 ? 0 : cursor - 1, ev.shiftKey); }
		else if (k === 'Home') { handled(); moveCursor(0, ev.shiftKey); }
		else if (k === 'End') { handled(); moveCursor(tbl.sorted.length - 1, ev.shiftKey); }
		else if (k === ' ' && cursor >= 0) { handled(); const n = tbl.sorted[cursor].name; sel = sel.includes(n) ? sel.filter((x) => x !== n) : [...sel, n]; }
		else if ((ev.ctrlKey || ev.metaKey) && k.toLowerCase() === 'a') { handled(); sel = entries.map((x) => x.name); }
		else if (k === 'Escape' && sel.length) { handled(); sel = []; }
		else if (k === 'Delete' && selected.length) { handled(); del(); }
		else if (k === 'F2' && one) { handled(); dlg('rename', { value: one.name }); }
		else if (k === 'Enter' && one) { handled(); open(one); }
		else if (k === 'Backspace' && cwd) { handled(); up(); }
	}
</script>

<svelte:window onkeydown={keydown} onbeforeunload={beforeUnload} />

<h1 class="sr-only">{$t('tools.file_manager')}</h1>
<div class="fm card">
	<div class="tb" role="toolbar" aria-label={$t('fm.toolbar')}>
		<button class="tbtn" onclick={() => dlg('file')}><FilePlus size={16} /> {$t('fm.new_file')}</button>
		<button class="tbtn" onclick={() => dlg('folder')}><FolderPlus size={16} /> {$t('fm.new_folder')}</button>
		<button class="tbtn" onclick={() => dlg('upload')}><Upload size={16} /> {$t('fm.upload')}</button>
		<button class="tbtn" disabled={!selected.some((e) => !e.is_dir)} onclick={download}><Download size={16} /> {$t('fm.download')}</button>
		<span class="sep"></span>
		<button class="tbtn" disabled={!one} onclick={() => dlg('copy', { value: '/' + cwd })}><Copy size={16} /> {$t('fm.copy')}</button>
		<button class="tbtn" disabled={!one} onclick={() => dlg('move', { value: '/' + cwd })}><MoveRight size={16} /> {$t('fm.move')}</button>
		<button class="tbtn" disabled={!one} onclick={() => dlg('rename', { value: one.name })}><Pencil size={16} /> {$t('fm.rename')}</button>
		<button class="tbtn" disabled={!one || one.is_dir} onclick={() => edit(one)}><FileCode size={16} /> {$t('fm.edit')}</button>
		<button class="tbtn" disabled={!selected.length} onclick={() => dlg('chmod', { value: (selected[0].perm).toString(8).padStart(3, '0') })}><Lock size={16} /> {$t('fm.permissions')}</button>
		<span class="sep"></span>
		<button class="tbtn" disabled={!selected.length} onclick={() => dlg('zip', { value: (one?.name ?? 'archive') + '.zip' })}><Archive size={16} /> {$t('fm.compress')}</button>
		<button class="tbtn" disabled={!one || !one.name.endsWith('.zip')} onclick={() => dlg('unzip', { value: '/' + cwd })}><PackageOpen size={16} /> {$t('fm.extract')}</button>
		<button class="tbtn danger" disabled={!selected.length} onclick={del}><Trash2 size={16} /> {$t('common.delete')}</button>
	</div>
	<div class="body">
		<nav class="tree" aria-label={$t('fm.folders')}>
			<button class:on={cwd === ''} onclick={() => load('')}><Home size={15} /> {$t('fm.home')}</button>
			{#each tops as d}
				<button class:on={cwd === d.name || cwd.startsWith(d.name + '/')} onclick={() => load(d.name)}><Folder size={15} /> {d.name}</button>
			{/each}
		</nav>
		<div class="list">
			<form class="pathbar" onsubmit={go}>
				<button type="button" class="btn sm" onclick={up} disabled={!cwd} aria-label={$t('fm.up')}><ArrowUp size={14} /></button>
				<div class="crumbs">
					<button type="button" class="linkbtn" onclick={() => load('')}>~</button>
					{#each crumbs as c, i}<span class="muted">/</span><button type="button" class="linkbtn" onclick={() => load(crumbs.slice(0, i + 1).join('/'))}>{c}</button>{/each}
				</div>
				<input bind:value={pathInput} class="mono" aria-label={$t('fm.path')} autocapitalize="off" spellcheck="false" />
				<button class="btn sm">{$t('fm.go')}</button>
				<button type="button" class="btn sm" onclick={() => load()} aria-label={$t('fm.reload')}><RefreshCw size={14} class={loading ? 'spin' : ''} /></button>
			</form>
			{#if pathNote}<p class="small pathnote" role="status">{$t(pathNote)}</p>{/if}
			<!-- svelte-ignore a11y_no_noninteractive_tabindex -->
			<div class="tw flist" bind:this={listEl} tabindex="0" role="region" aria-label={$t('fm.file_list_label', { path: '/' + cwd })} aria-describedby="fm-keys"
				onfocus={() => { if (cursor < 0 && tbl.sorted.length && !sel.length) cursor = -1; }}>
			<table class="table" aria-rowcount={entries.length}>
				<thead><tr>
					<th style="width:28px"><input type="checkbox" aria-label={$t('fm.select_all')} checked={sel.length > 0 && sel.length === entries.length} onchange={(e) => (sel = e.currentTarget.checked ? entries.map((x) => x.name) : [])} /></th>
					<SortTh {tbl} key="name" label={$t('fm.name')} /><SortTh {tbl} key="size" label={$t('fm.size')} cls="r" /><SortTh {tbl} key="mod" label={$t('fm.modified')} /><SortTh {tbl} key="perm" label={$t('fm.perms')} />
				</tr></thead>
				<tbody>
					{#each tbl.sorted.slice(0, shownRows) as e, i (e.name)}
						{@const Icon = icon(e)}
						<tr data-i={i} class:sel={sel.includes(e.name)} class:cur={i === cursor} aria-selected={sel.includes(e.name)} onclick={(ev) => toggle(e.name, ev)} ondblclick={() => open(e)}>
							<td><input type="checkbox" checked={sel.includes(e.name)} aria-label={$t('fm.select_item', { name: e.name })} tabindex="-1" /></td>
							<td><span class="nm"><Icon size={16} class={e.is_dir ? 'dir' : ''} /> <button class="linkbtn" onclick={(ev) => { ev.stopPropagation(); open(e); }}>{e.name}</button></span></td>
							<td class="r">{e.is_dir ? '—' : $fmt.bytes(e.size)}</td>
							<td class="small">{$fmt.date(e.mod_unix)}</td>
							<td class="mono">{e.perm.toString(8).padStart(4, '0')}</td>
						</tr>
					{:else}
						<tr><td colspan="5" class="empty">{loading ? $t('common.loading') : $t('fm.empty')}</td></tr>
					{/each}
					{#if tbl.sorted.length > shownRows}
						<tr class="more"><td colspan="5"><button type="button" class="linkbtn" bind:this={moreEl} onclick={() => (shownRows += CHUNK)}>{$t('fm.show_more', { n: tbl.sorted.length - shownRows })}</button></td></tr>
					{/if}
				</tbody>
			</table>
			</div>
			<div class="status muted small"><span aria-live="polite">{$t('fm.status', { n: entries.length, s: sel.length })}</span> <span class="keys" id="fm-keys">{$t('fm.shortcuts')}</span></div>
		</div>
	</div>
</div>

<Modal bind:open={dlgOpen} title={dialog ? $t('fm.dlg_' + dialog.kind) : ''}>
	{#if dialog}
		<form id="fmdlg" onsubmit={submitDlg}>
			{#if dialog.kind === 'upload'}
				<label class="field"><span>{$t('fm.upload_to', { path: '/' + cwd })}</span><input id="fm-upload" type="file" multiple onchange={(e) => { files = e.currentTarget.files; uploadError = false; }}
					aria-invalid={uploadError ? 'true' : undefined} aria-describedby="fm-upload-h" /></label>
				{#if uploadError}<p class="field-err" role="alert">{uploadError.key ? $t(uploadError.key, uploadError.params) : $t('val.file_required')}</p>{/if}
				{#if files?.length}<p class="small">{$t('fm.upload_selected', { n: files.length })}</p>{/if}
				<small class="muted" id="fm-upload-h">{$t('fm.upload_limit', { file: $fmt.bytes(serverLimits.uploadMaxFile || 268435456), request: $fmt.bytes(serverLimits.uploadMaxRequest || serverLimits.uploadMaxFile || 268435456) })}</small>
			{:else if dialog.kind === 'chmod'}
				<table class="table perms">
					<thead><tr><th><span class="sr-only">{$t('fm.who')}</span></th><th>{$t('fm.read')}</th><th>{$t('fm.write')}</th><th>{$t('fm.execute')}</th></tr></thead>
					<tbody>
						{#each bits as [who, shift]}
							<tr><td>{$t('fm.' + who)}</td>
								{#each [[4, 'read'], [2, 'write'], [1, 'execute']] as [b, what]}<td><input type="checkbox" checked={bit(dialog.value, shift, b)} onchange={(e) => setBit(shift, b, e.currentTarget.checked)} aria-label={$t('fm.perm_label', { who: $t('fm.' + who), what: $t('fm.' + what) })} /></td>{/each}
							</tr>
						{/each}
					</tbody>
				</table>
				<label class="field" style="margin-top:12px"><span>{$t('fm.octal')}</span><input bind:value={dialog.value} pattern="[0-7]{'{3}'}" maxlength="3" required data-err="val.octal" class="mono" style="max-width:100px" /></label>
			{:else}
				<label class="field"><span>{$t('fm.field_' + dialog.kind)}</span><input id="fm-dlg-val" bind:value={dialog.value} required class="mono" autocapitalize="off" spellcheck="false" use:customValidity={nameProblem} aria-invalid={nameProblem ? 'true' : undefined} />
					{#if nameProblem && dialog.value}<small class="field-err">{$t(nameProblem)}</small>{:else if nameTrimmed}<small>{$t('fm.name_trimmed')}</small>{/if}</label>
				{#if ['move', 'copy', 'unzip'].includes(dialog.kind)}<small class="muted">{$t('fm.dest_help')}</small>{/if}
			{/if}
		</form>
	{/if}
	{#snippet footer()}<button class="btn" onclick={() => (dlgOpen = false)}>{$t('common.cancel')}</button><button class="btn primary" form="fmdlg" disabled={busy}>{$t('common.ok')}</button>{/snippet}
</Modal>

<Modal bind:open={edOpen} title={(dirty ? '● ' : '') + (editor?.path ?? '')} width={980} canClose={canCloseEditor} initial="textarea">
	{#if editor}<textarea class="code" bind:value={editor.content} spellcheck="false" aria-label={$t('fm.editing', { name: editor.name })} onkeydown={edKey}></textarea>
		<p class="muted small edhint">{dirty ? $t('fm.unsaved') : $t('fm.no_changes')} · {$t('fm.save_shortcut')}</p>{/if}
	{#snippet footer()}<button class="btn" onclick={closeEditor}>{$t('common.close')}</button><button class="btn primary" onclick={saveEdit} disabled={busy || !dirty}>{$t('fm.save_changes')}</button>{/snippet}
</Modal>

<style>
	.fm { overflow: hidden; }
	.tb { display: flex; flex-wrap: wrap; gap: 2px; padding: 6px 8px; border-bottom: 1px solid var(--border); background: var(--card-2); }
	.tbtn { display: inline-flex; align-items: center; gap: 6px; padding: 6px 9px; border: 0; background: none; border-radius: 5px; font: inherit; font-size: 13px; color: var(--text); cursor: pointer; }
	.tbtn:hover:not(:disabled) { background: var(--blue-soft); color: var(--link); }
	.tbtn:disabled { opacity: 0.4; cursor: default; }
	.tbtn.danger { color: var(--red); }
	.sep { width: 1px; background: var(--border); margin: 4px 4px; }
	.body { display: grid; grid-template-columns: 200px minmax(0, 1fr); min-height: 520px; }
	.tree { border-right: 1px solid var(--border); padding: 8px; display: flex; flex-direction: column; gap: 1px; background: var(--card); }
	.tree button { display: flex; align-items: center; gap: 8px; padding: 6px 8px; border: 0; background: none; font: inherit; font-size: 13px; color: var(--text); cursor: pointer; border-radius: 5px; text-align: left; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
	.tree button :global(svg) { color: var(--amber); flex: none; }
	.tree button:hover { background: var(--card-2); }
	.tree button.on { background: var(--blue-soft); color: var(--blue-text); }
	.pathnote { margin: 0; padding: 6px 12px; background: var(--amber-soft); color: var(--amber-text); }
	tr.more td { text-align: center; padding: 10px; }
	.pathbar { display: flex; gap: 8px; align-items: center; padding: 8px 12px; border-bottom: 1px solid var(--border); }
	.crumbs { display: flex; gap: 4px; align-items: center; white-space: nowrap; overflow: hidden; max-width: 40%; }
	@media (max-width: 600px) { .crumbs { display: none; } .pathbar { padding: 8px; gap: 6px; } .tb { gap: 0; } .tbtn { padding: 6px 7px; } .tbtn :global(svg) { flex: none; } }
	.pathbar input { flex: 1; min-height: 28px; padding: 3px 8px; }
	tr.sel td { background: var(--blue-soft) !important; }
	tr.cur td:first-child { box-shadow: inset 3px 0 0 var(--primary); }
	.flist:focus-visible tr.cur td { outline: 1px dotted var(--primary); outline-offset: -1px; }
	.keys { float: right; }
	.edhint { margin: 6px 0 0; }
	@media (max-width: 900px) { .keys { display: none; } }
	tbody tr { cursor: default; user-select: none; }
	.nm { display: inline-flex; align-items: center; gap: 8px; }
	.nm :global(svg) { color: var(--muted); flex: none; }
	.nm :global(svg.dir) { color: var(--amber); }
	.r { text-align: right; }
	.status { padding: 8px 14px; border-top: 1px solid var(--border); }
	.code { width: 100%; min-height: 60vh; font-family: var(--mono); font-size: 13px; line-height: 1.55; tab-size: 4; white-space: pre; background: var(--card-2); }
	.perms td, .perms th { text-align: center; }
	@media (max-width: 760px) { .body { grid-template-columns: minmax(0, 1fr); } .tree { display: none; } }
	.list { min-width: 0; }
	.nm { white-space: nowrap; }
	.nm .linkbtn { text-align: left; }
	td.small { white-space: nowrap; }
</style>
