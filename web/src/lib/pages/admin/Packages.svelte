<script>
	import { Package, Plus, Pencil, Trash2 } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t } from '$lib/i18n/index.js';
	import { session } from '$lib/stores.js';
	import { showErr, ok, ask, qs, showWarnings } from '$lib/util.js';
	import { maxLen, customValidity } from '$lib/a11y.js';
	import { fromApi, toApi, showLimit, sendWithLimits, noteValues } from '$lib/limits.js';
	import PageHead from '$lib/components/PageHead.svelte';
	import Modal from '$lib/components/Modal.svelte';
	import LimitInput from '$lib/components/LimitInput.svelte';

	let all = $state([]);
	let open = $state(false);
	let edit = $state(null);
	let busy = $state(false);
	let me = $derived($session?.user);
	let isReseller = $derived(me?.role === 'reseller');
	// R2-UX-03: a reseller only works with the packages it owns (older servers also list the
	// administrator's global packages, which a reseller cannot use anyway).
	let list = $derived(isReseller ? all.filter((p) => p.owner_id === me.id) : all);
	// key, label, unit, min (when not unlimited), upper bound
	const fields = [
		['disk_mb', 'pkg.disk', 'MB', 1, 1e9], ['bandwidth_mb', 'pkg.bandwidth', 'MB', 1, 1e10], ['max_domains', 'pkg.domains', '', 0, 1e6],
		['max_subdomains', 'pkg.subdomains', '', 0, 1e6], ['max_aliases', 'pkg.aliases', '', 0, 1e6], ['max_email', 'pkg.email', '', 0, 1e6],
		['mail_quota_mb', 'pkg.mail_quota', 'MB', 1, 1e8], ['max_db', 'pkg.db', '', 0, 1e6], ['max_ftp', 'pkg.ftp', '', 0, 1e6],
		['cpu_percent', 'pkg.cpu', '%', 1, 25600], ['memory_mb', 'pkg.memory', 'MB', 1, 1e7], ['max_tasks', 'pkg.tasks', '', 1, 1e6]
	];
	const KEYS = fields.map((f) => f[0]);
	const blank = { name: '', disk_mb: 10240, bandwidth_mb: 102400, max_domains: 5, max_subdomains: 20, max_aliases: 10, max_email: 50, max_db: 10, max_ftp: 10, mail_quota_mb: 1024, cpu_percent: 100, memory_mb: 1024, max_tasks: 200, php_version: '' };
	// R2-UX-40: letters (any script), digits, space, dot, dash, underscore; starts with a letter or digit
	const NAME_RE = /^[\p{L}\p{N}][\p{L}\p{N} ._-]*$/u;
	let nameProblem = $derived(edit && !edit.id && edit.name.trim() && (!NAME_RE.test(edit.name.trim()) || edit.name.includes('..')) ? 'val.pkg_name' : null);

	async function load() { try { all = await api.get('/admin/packages'); noteValues(all, KEYS); } catch (e) { showErr(e); } }
	load();
	function startEdit(p) {
		const lim = {};
		for (const [k, , , min] of fields) lim[k] = fromApi(p[k], Math.max(min, 1));
		edit = { id: p.id, name: p.name, php_version: p.php_version ?? '', lim };
		open = true;
	}
	if (qs('new') === '1') startEdit(blank);
	async function save(e) {
		e.preventDefault();
		if (nameProblem) return;
		busy = true;
		const body = { name: edit.name.trim(), php_version: edit.php_version };
		for (const k of KEYS) body[k] = toApi(edit.lim[k]);
		try {
			const r = await sendWithLimits((b) => (edit.id ? api.put('/admin/packages/' + edit.id, b) : api.post('/admin/packages', b)), body, KEYS);
			// R2-UX-04: a reseller's package is stored with its username in front — say so
			if (!edit.id && r?.name && r.name !== body.name) ok('pkg.prefixed', { name: r.name }); else ok('common.saved');
			showWarnings(r); open = false; load();
		} catch (err) { showErr(err); }
		busy = false;
	}
	async function del(p) { if (!ask('pkg.confirm_delete', { name: p.name })) return; try { await api.del('/admin/packages/' + p.id); ok('common.deleted'); load(); } catch (err) { showErr(err); } }
</script>

<PageHead title={$t('pkg.title')} desc={$t('pkg.desc')} icon={Package} crumbs={{ label: $t('shell.breadcrumbs'), items: [{ href: '/', text: $t('nav.home') }, { text: $t('groups.packages') }] }}>
	{#snippet actions()}<button class="btn primary" onclick={() => startEdit(blank)}><Plus size={16} /> {$t('tools.add_package')}</button>{/snippet}
</PageHead>
<div class="card tw">
	<table class="table">
		<thead><tr><th>{$t('pkg.name')}</th><th>{$t('pkg.disk')}</th><th>{$t('pkg.bandwidth')}</th><th>{$t('pkg.domains')}</th><th>{$t('pkg.email')}</th><th>{$t('pkg.db')}</th><th>CPU</th><th>RAM</th><th>{$t('pkg.accounts')}</th><th><span class="sr-only">{$t('common.actions')}</span></th></tr></thead>
		<tbody>
			{#each list as p}
				<tr><td><b>{p.name}</b></td><td>{showLimit(p.disk_mb, 'MB')}</td><td>{showLimit(p.bandwidth_mb, 'MB')}</td><td>{showLimit(p.max_domains)}</td><td>{showLimit(p.max_email)}</td><td>{showLimit(p.max_db)}</td><td>{showLimit(p.cpu_percent, '%')}</td><td>{showLimit(p.memory_mb, 'MB')}</td><td>{p.accounts}</td>
					<td><div class="actions"><button class="linkbtn" onclick={() => startEdit(p)} aria-label={$t('pkg.edit', { name: p.name })}><Pencil size={13} /> {$t('common.edit')}</button><button class="linkbtn danger" onclick={() => del(p)} aria-label={$t('pkg.delete_named', { name: p.name })} title={$t('common.delete')}><Trash2 size={13} /></button></div></td></tr>
			{:else}<tr><td colspan="10" class="empty">{$t('common.none')}</td></tr>{/each}
		</tbody>
	</table>
</div>

<Modal bind:open title={edit?.id ? $t('pkg.edit', { name: edit.name }) : $t('tools.add_package')} width={780}>
	{#if edit}
		<form id="pkgf" onsubmit={save}>
			<label class="field"><span>{$t('pkg.name')}</span>
				{#if isReseller && !edit.id}
					<div class="input-group"><span class="addon">{me.username}_</span><input id="pkg-name" bind:value={edit.name} required use:maxLen={64 - me.username.length - 1} use:customValidity={nameProblem} aria-invalid={nameProblem ? 'true' : undefined} autocapitalize="off" spellcheck="false" /></div>
				{:else}
					<input id="pkg-name" bind:value={edit.name} required use:maxLen={64} disabled={!!edit.id} use:customValidity={nameProblem} aria-invalid={nameProblem ? 'true' : undefined} autocapitalize="off" spellcheck="false" />
				{/if}
				{#if nameProblem}<small class="field-err">{$t(nameProblem)}</small>{:else if isReseller && !edit.id}<small>{$t('pkg.prefix_help', { prefix: me.username + '_' })}</small>{/if}
			</label>
			<div class="grid3">
				{#each fields as [k, l, u, min, max]}
					<LimitInput id={'pkg-' + k} label={$t(l)} unit={u} {min} {max} bind:value={edit.lim[k]} allowUnlimited={!isReseller || k === 'bandwidth_mb' || k === 'mail_quota_mb'} />
				{/each}
			</div>
			<p class="muted small">{$t('pkg.zero_none')}</p>
		</form>
	{/if}
	{#snippet footer()}<button class="btn" onclick={() => (open = false)}>{$t('common.cancel')}</button><button class="btn primary" form="pkgf" disabled={busy}>{$t('common.save')}</button>{/snippet}
</Modal>
