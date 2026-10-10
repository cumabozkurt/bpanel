<script>
	import { Gauge, Plus, Pencil, Trash2 } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t, fmt } from '$lib/i18n/index.js';
	import { session } from '$lib/stores.js';
	import { showErr, ok, ask } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';
	import Modal from '$lib/components/Modal.svelte';
	import UsagePanel from '$lib/components/UsagePanel.svelte';

	const F = ['cpu_percent', 'cpu_weight', 'mem_max_mb', 'mem_high_mb', 'io_read_bps', 'io_write_bps', 'io_read_iops', 'io_write_iops', 'tasks_max', 'inode_limit', 'disk_mb', 'entry_procs'];
	let me = $derived($session?.user);
	let isAdmin = $derived(me?.role === 'admin');
	let status = $state(null);
	let profiles = $state([]);
	let top = $state([]);
	let accounts = $state([]);
	let acct = $state('');
	let lim = $state(null);
	let open = $state(false);
	let edit = $state(null);
	let busy = $state(false);

	async function load() {
		try {
			[status, profiles, top] = await Promise.all([
				api.get('/admin/isolation/status').catch(() => null),
				api.get('/admin/limit-profiles').then((r) => r.items),
				api.get('/admin/usage/top').then((r) => r.items)
			]);
			accounts = (await api.get('/admin/accounts?limit=500')).items ?? [];
		} catch (e) { showErr(e); }
	}
	load();
	async function loadLimits() {
		lim = null;
		if (!acct) return;
		try {
			const r = await api.get(`/admin/accounts/${acct}/limits`);
			lim = { profile_id: r.profile_id ?? '', ov: Object.fromEntries(F.map((k) => [k, r.overrides?.[k] ?? ''])) };
		} catch (e) { showErr(e); }
	}
	$effect(() => { acct; loadLimits(); });
	function newProfile() { edit = { name: '', ...Object.fromEntries(F.map((k) => [k, 0])) }; open = true; }
	function editProfile(p) { edit = { ...p }; open = true; }
	async function save(e) {
		e.preventDefault();
		busy = true;
		const body = { name: edit.name, ...Object.fromEntries(F.map((k) => [k, Number(edit[k]) || 0])) };
		try {
			if (edit.id) await api.put(`/admin/limit-profiles/${edit.id}`, body); else await api.post('/admin/limit-profiles', body);
			open = false; ok('iso.saved'); load();
		} catch (err) { showErr(err); }
		busy = false;
	}
	async function del(p) {
		if (!ask('iso.confirm_delete', { name: p.name })) return;
		try { await api.del(`/admin/limit-profiles/${p.id}`); ok('iso.deleted'); load(); } catch (e) { showErr(e); }
	}
	async function saveLimits(e) {
		e.preventDefault();
		busy = true;
		const overrides = {};
		for (const k of F) if (lim.ov[k] !== '' && lim.ov[k] !== null) overrides[k] = Number(lim.ov[k]);
		try {
			const r = await api.put(`/admin/accounts/${acct}/limits`, { profile_id: lim.profile_id === '' ? null : Number(lim.profile_id), overrides });
			if (r.applied) ok(r.status === 'applied' ? 'iso.applied' : 'iso.applied_files_only'); else showErr({ code: r.code });
		} catch (err) { showErr(err); }
		busy = false;
	}
	const show = (v) => (v ? v : '∞');
</script>

<PageHead title={$t('iso.title')} desc={$t('iso.desc')} icon={Gauge}>
	{#snippet actions()}{#if isAdmin}<button class="btn primary" onclick={newProfile}><Plus size={15} /> {$t('iso.new_profile')}</button>{/if}{/snippet}
</PageHead>
{#if status && !status.supported}<div class="card pad warn" role="status">{$t('iso.unsupported', { reason: status.reason || '' })}</div>{/if}

<h2>{$t('iso.profiles')}</h2>
<div class="card tw">
	<table class="table">
		<thead><tr><th>{$t('iso.name')}</th><th>{$t('iso.f.cpu_percent')}</th><th>{$t('iso.f.mem_max_mb')}</th><th>{$t('iso.f.tasks_max')}</th><th>{$t('iso.f.io_read_bps')}</th><th>{$t('iso.accounts')}</th><th></th></tr></thead>
		<tbody>
			{#each profiles as p (p.id)}
				<tr><td><b>{p.name}</b></td><td>{show(p.cpu_percent)}</td><td>{show(p.mem_max_mb)}</td><td>{show(p.tasks_max)}</td><td>{show(p.io_read_bps)}</td><td>{p.accounts}</td>
					<td class="right">{#if isAdmin}<button class="btn ghost sm" aria-label={$t('common.edit')} onclick={() => editProfile(p)}><Pencil size={14} /></button><button class="btn ghost sm" aria-label={$t('common.delete')} onclick={() => del(p)}><Trash2 size={14} /></button>{/if}</td></tr>
			{:else}<tr><td colspan="7" class="empty">{$t('iso.no_profiles')}</td></tr>{/each}
		</tbody>
	</table>
</div>

<h2>{$t('iso.top')}</h2>
<div class="card tw">
	<table class="table">
		<thead><tr><th>{$t('iso.account')}</th><th>{$t('iso.cpu')}</th><th>{$t('iso.memory')}</th><th>{$t('iso.io')}</th><th>{$t('iso.pids')}</th></tr></thead>
		<tbody>
			{#each top as x (x.id)}
				<tr><td><button class="btn ghost sm" onclick={() => (acct = String(x.id))}>{x.username}</button></td><td>{x.cpu_pct.toFixed(1)}%</td><td>{$fmt.bytes(x.mem_bytes)}</td><td>{$fmt.bytes(x.io_bytes)}</td><td>{x.pids}</td></tr>
			{:else}<tr><td colspan="5" class="empty">{$t('iso.no_data')}</td></tr>{/each}
		</tbody>
	</table>
</div>

<h2>{$t('iso.account_limits')}</h2>
<div class="card pad">
	<label class="field"><span>{$t('iso.account')}</span>
		<select bind:value={acct}><option value="">—</option>{#each accounts.filter((a) => a.role !== 'admin') as a (a.id)}<option value={String(a.id)}>{a.username}</option>{/each}</select>
	</label>
	{#if lim}
		<form onsubmit={saveLimits}>
			<label class="field"><span>{$t('iso.profile')}</span>
				<select bind:value={lim.profile_id}><option value="">{$t('iso.none')}</option>{#each profiles as p (p.id)}<option value={p.id}>{p.name}</option>{/each}</select>
			</label>
			<p class="small muted">{$t('iso.override_help')}</p>
			<div class="grid3">
				{#each F as k}<label class="field"><span>{$t('iso.f.' + k)}</span><input type="number" min="0" bind:value={lim.ov[k]} /></label>{/each}
			</div>
			<button class="btn primary" disabled={busy}>{$t('iso.apply')}</button>
		</form>
		<h3>{$t('iso.usage')}</h3>
		<UsagePanel src={`/admin/accounts/${acct}/usage`} />
	{/if}
</div>

<Modal bind:open title={edit?.id ? $t('iso.edit_profile', { name: edit.name }) : $t('iso.new_profile')} width={780}>
	{#if edit}
		<form id="isof" onsubmit={save}>
			<label class="field"><span>{$t('iso.name')}</span><input bind:value={edit.name} required maxlength="64" /></label>
			<div class="grid3">
				{#each F as k}<label class="field"><span>{$t('iso.f.' + k)}</span><input type="number" min="0" bind:value={edit[k]} /></label>{/each}
			</div>
			<p class="muted small">{$t('iso.zero_unlimited')}</p>
		</form>
	{/if}
	{#snippet footer()}<button class="btn" onclick={() => (open = false)}>{$t('common.cancel')}</button><button class="btn primary" form="isof" disabled={busy}>{$t('common.save')}</button>{/snippet}
</Modal>
