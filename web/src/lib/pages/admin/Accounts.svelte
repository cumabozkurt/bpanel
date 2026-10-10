<script>
	import { ListChecks, UserPlus, LogIn, PauseCircle, PlayCircle, Trash2, KeyRound, Package, Download, ChevronLeft, ChevronRight } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t, fmt } from '$lib/i18n/index.js';
	import { session } from '$lib/stores.js';
	import { showErr, ok, ask, qs } from '$lib/util.js';
	import { maxLen } from '$lib/a11y.js';
	import PageHead from '$lib/components/PageHead.svelte';
	import Modal from '$lib/components/Modal.svelte';
	import PasswordField from '$lib/components/PasswordField.svelte';
	import SortTh from '$lib/components/SortTh.svelte';
	import Pager from '$lib/components/Pager.svelte';
	import { TableState } from '$lib/table.svelte.js';
	import { matches } from '$lib/search.js';

	let list = $state([]);
	let pkgs = $state([]);
	let q = $state(qs('q') || '');
	let status = $state(qs('status') || '');
	let isAdmin = $derived($session?.user?.role === 'admin');
	let role = $state(qs('role') || '');
	// WHM-style deep links (R2-UX-34): /accounts?action=suspend|terminate|password highlights that action
	const action = ['suspend', 'terminate', 'password'].includes(qs('action')) ? qs('action') : '';
	let dlg = $state(null);
	let dlgOpen = $state(false);
	let busy = $state(false);
	// R2-UX-03: packages a reseller can assign are its own
	let myPkgs = $derived(isAdmin ? pkgs : pkgs.filter((p) => p.owner_id === $session?.user?.id));

	// Server-side paging (perf): the first request asks for FIRST rows; when the server reports more
	// (X-Total-Count), the list switches to ?limit=&offset=&q= paging. Small servers keep the
	// instant client-side search, sort and filters.
	const FIRST = 200;
	let serverMode = $state(false);
	let total = $state(0);
	let offset = $state(0);
	let size = $state(50);
	async function loadPage() {
		const p = new URLSearchParams({ limit: String(size), offset: String(offset) });
		if (q.trim()) p.set('q', q.trim());
		if (status) p.set('status', status);
		if (role) p.set('role', role);
		const r = await api.page('/admin/accounts?' + p);
		list = r.data ?? [];
		total = r.total ?? list.length;
	}
	async function load() {
		try {
			if (serverMode) await loadPage();
			else {
				const r = await api.page('/admin/accounts?limit=' + FIRST);
				if (r.total !== null && r.total > (r.data?.length ?? 0)) { serverMode = true; total = r.total; await loadPage(); }
				else list = r.data ?? [];
			}
			pkgs = await api.get('/admin/packages');
		} catch (e) { showErr(e); }
	}
	load();
	let timer;
	$effect(() => {
		q; status; role;
		if (!serverMode) return;
		clearTimeout(timer);
		timer = setTimeout(() => { offset = 0; loadPage().catch(showErr); }, 300);
	});
	let shown = $derived(list.filter((a) => (!status || a.status === status) && (!role || a.role === role) && (serverMode || !q.trim() || matches([a.username, a.primary_domain, a.email, a.package_name, a.owner_name].join(' '), q))));
	const tbl = new TableState(() => shown, { key: 'primary_domain' });
	$effect(() => { q; status; role; tbl.reset(); });
	let rows = $derived(serverMode ? tbl.sorted : tbl.page);
	function goPage(n) { offset = Math.max(0, Math.min(n, Math.max(0, total - 1))); loadPage().catch(showErr); }

	async function act(fn, msg, params) { busy = true; try { await fn(); ok(msg, params); dlgOpen = false; load(); } catch (e) { showErr(e); } busy = false; }
	function suspend(a) { dlg = { kind: 'suspend', a, reason: '' }; dlgOpen = true; }
	function unsuspend(a) { act(() => api.post(`/admin/accounts/${a.id}/unsuspend`), 'acc.unsuspended', { user: a.username }); }
	function terminate(a) {
		if (!ask('acc.confirm_terminate', { user: a.username, domain: a.primary_domain })) return;
		act(() => api.del('/admin/accounts/' + a.id), 'acc.terminated', { user: a.username });
	}
	async function loginAs(a) { try { const r = await api.post(`/admin/accounts/${a.id}/login`); window.open(r.url, '_blank', 'noopener'); } catch (e) { showErr(e); } }
	function submit(e) {
		e.preventDefault();
		const a = dlg.a;
		if (dlg.kind === 'suspend') act(() => api.post(`/admin/accounts/${a.id}/suspend`, { reason: dlg.reason.trim() }), 'acc.suspended', { user: a.username });
		if (dlg.kind === 'password') act(() => api.post(`/admin/accounts/${a.id}/password`, { password: dlg.password }), 'common.saved');
		if (dlg.kind === 'package') act(() => api.put(`/admin/accounts/${a.id}/package`, { package_id: Number(dlg.package_id) }), 'common.saved');
	}
	// G4: CSV export of the rows on screen (WHM "Download CSV")
	function csv() {
		const esc = (v) => '"' + String(v ?? '').replace(/"/g, '""') + '"';
		const head = ['domain', 'username', 'role', 'package', 'owner', 'email', 'status', 'created'];
		const body = shown.map((a) => [a.primary_domain, a.username, a.role, a.package_name, a.owner_name, a.email, a.status, a.created_at ? new Date(a.created_at * 1000).toISOString() : ''].map(esc).join(','));
		const url = URL.createObjectURL(new Blob([[head.join(','), ...body].join('\r\n') + '\r\n'], { type: 'text/csv' }));
		const el = document.createElement('a');
		el.href = url; el.download = 'accounts.csv'; el.click();
		setTimeout(() => URL.revokeObjectURL(url), 1000);
	}
</script>

<PageHead title={role === 'reseller' && isAdmin ? $t('tools.list_resellers') : $t('acc.title')} desc={$t('acc.desc')} icon={ListChecks}
	crumbs={{ label: $t('shell.breadcrumbs'), items: [{ href: '/', text: $t('nav.home') }, { text: $t(role === 'reseller' && isAdmin ? 'groups.resellers' : 'groups.account_info') }] }}>
	{#snippet actions()}
		<button class="btn" onclick={csv} disabled={!shown.length}><Download size={15} /> {$t('acc.export_csv')}</button>
		<a class="btn primary" href={role === 'reseller' && isAdmin ? '/accounts/new?role=reseller' : '/accounts/new'}><UserPlus size={16} /> {role === 'reseller' && isAdmin ? $t('tools.create_reseller') : $t('tools.create_account')}</a>
	{/snippet}
</PageHead>

{#if action}<div class="alert info" role="status">{$t('acc.pick_' + action)}</div>{/if}

<div class="card">
	<div class="toolbar">
		<input type="search" bind:value={q} placeholder={$t('acc.search')} aria-label={$t('acc.search')} />
		<select bind:value={status} style="width:auto" aria-label={$t('acc.status')}><option value="">{$t('acc.all_status')}</option><option value="active">{$t('acc.active')}</option><option value="suspended">{$t('acc.suspended')}</option></select>
		{#if isAdmin}<select bind:value={role} style="width:auto" aria-label={$t('acc.role')}><option value="">{$t('acc.all_roles')}</option><option value="user">{$t('acc.role_user')}</option><option value="reseller">{$t('acc.role_reseller')}</option></select>{/if}
		<span class="grow"></span><span class="muted small">{$t('common.count', { n: serverMode ? total : shown.length })}</span>
	</div>
	<div class="tw">
	<table class="table">
		<thead><tr><SortTh {tbl} key="primary_domain" label={$t('acc.domain')} /><SortTh {tbl} key="username" label={$t('acc.username')} /><SortTh {tbl} key="package_name" label={$t('acc.package')} />{#if isAdmin}<SortTh {tbl} key="owner_name" label={$t('acc.owner')} />{/if}<SortTh {tbl} key="created_at" label={$t('acc.created')} /><SortTh {tbl} key="status" label={$t('acc.status')} /><th><span class="sr-only">{$t('common.actions')}</span></th></tr></thead>
		<tbody>
			{#each rows as a (a.id)}
				<tr>
					<td><b>{a.primary_domain}</b><div class="muted small">{a.email}</div></td>
					<td class="mono">{a.username} {#if a.role === 'reseller'}<span class="badge teal">{$t('acc.role_reseller')}</span>{/if}</td>
					<td>{a.package_name}</td>
					{#if isAdmin}<td>{a.owner_name}</td>{/if}
					<td class="small">{$fmt.date(a.created_at)}</td>
					<td>{#if a.status === 'suspended'}<span class="badge red" title={a.suspend_reason}>{$t('acc.suspended')}</span>{:else}<span class="badge green">{$t('acc.active')}</span>{/if}</td>
					<td><div class="actions">
						<button class="linkbtn" onclick={() => loginAs(a)} title={$t('acc.login_as')} aria-label={$t('acc.login_as_named', { user: a.username })}><LogIn size={13} /> {$t('acc.login')}</button>
						<button class="linkbtn" onclick={() => { dlg = { kind: 'package', a, package_id: a.package_id }; dlgOpen = true; }} title={$t('acc.package')} aria-label={$t('acc.change_package_named', { user: a.username })}><Package size={13} /></button>
						<button class="linkbtn" class:hl={action === 'password'} onclick={() => { dlg = { kind: 'password', a, password: '' }; dlgOpen = true; }} title={$t('common.password')} aria-label={$t('acc.change_password_named', { user: a.username })}><KeyRound size={13} />{#if action === 'password'} {$t('common.password')}{/if}</button>
						{#if a.status === 'suspended'}<button class="linkbtn" class:hl={action === 'suspend'} onclick={() => unsuspend(a)}><PlayCircle size={13} /> {$t('acc.unsuspend')}</button>
						{:else}<button class="linkbtn" class:hl={action === 'suspend'} onclick={() => suspend(a)}><PauseCircle size={13} /> {$t('acc.suspend')}</button>{/if}
						<button class="linkbtn danger" class:hl={action === 'terminate'} onclick={() => terminate(a)}><Trash2 size={13} /> {$t('acc.terminate')}</button>
					</div></td>
				</tr>
			{:else}<tr><td colspan="7" class="empty">{$t('common.none')}</td></tr>{/each}
		</tbody>
	</table>
	</div>
	{#if serverMode}
		<nav class="pager" aria-label={$t('common.pagination')}>
			<span class="muted small">{$t('common.range', { from: total ? offset + 1 : 0, to: Math.min(total, offset + list.length), total })}</span>
			<span class="grow"></span>
			<button type="button" class="btn sm" disabled={offset <= 0} onclick={() => goPage(offset - size)} aria-label={$t('common.prev_page')}><ChevronLeft size={14} /></button>
			<span class="small" aria-live="polite">{$t('common.page_of', { n: Math.floor(offset / size) + 1, total: Math.max(1, Math.ceil(total / size)) })}</span>
			<button type="button" class="btn sm" disabled={offset + size >= total} onclick={() => goPage(offset + size)} aria-label={$t('common.next_page')}><ChevronRight size={14} /></button>
		</nav>
	{:else}
		<Pager {tbl} />
	{/if}
</div>

<Modal bind:open={dlgOpen} title={dlg ? $t('acc.dlg_' + dlg.kind, { user: dlg.a.username }) : ''}>
	{#if dlg}
		<form id="accdlg" onsubmit={submit}>
			{#if dlg.kind === 'suspend'}
				<label class="field"><span>{$t('acc.reason')}</span><input id="acc-reason" bind:value={dlg.reason} placeholder={$t('acc.reason_ph')} use:maxLen={500} /></label>
				<p class="muted small">{$t('acc.suspend_help')}</p>
			{:else if dlg.kind === 'password'}
				<PasswordField bind:value={dlg.password} id="accpw" />
			{:else}
				<label class="field"><span>{$t('acc.package')}</span><select bind:value={dlg.package_id}>{#each myPkgs as p}<option value={p.id}>{p.name}</option>{/each}</select></label>
			{/if}
		</form>
	{/if}
	{#snippet footer()}<button class="btn" onclick={() => (dlgOpen = false)}>{$t('common.cancel')}</button><button class="btn primary" form="accdlg" disabled={busy}>{$t('common.ok')}</button>{/snippet}
</Modal>

<style>
	.hl { font-weight: 700; text-decoration: underline; text-underline-offset: 3px; }
	.pager { display: flex; align-items: center; gap: 8px; padding: 10px 14px; border-top: 1px solid var(--border); flex-wrap: wrap; }
</style>
