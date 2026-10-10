<script>
	// v0.4 Shield policy editor: global rows (admins) and per-account rows.
	// An empty action = inherit. Resellers edit only their own accounts and the
	// API refuses script/executable actions weaker than the global policy.
	import { Save } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t } from '$lib/i18n/index.js';
	import { showErr, ok } from '$lib/util.js';

	let { accounts = [] } = $props();
	const classes = ['script', 'executable', 'archive', 'other'];
	let data = $state(null);
	let scope = $state('global');
	let rows = $state([]);
	let busy = $state(false);

	function rowsFor(sc, d) {
		const set = sc === 'global' ? d.global : (d.accounts.find((a) => String(a.account_id) === sc) ?? { rows: [] });
		return classes.map((c) => {
			const r = set.rows.find((x) => x.file_class === c) ?? {};
			return { file_class: c, on_unavailable: r.on_unavailable ?? '', on_suspicious: r.on_suspicious ?? '' };
		});
	}
	async function load() {
		try {
			data = await api.get('/admin/shield/policies');
			if (!data.can_edit_global && scope === 'global') scope = accounts[0] ? String(accounts[0].id) : '';
			rows = scope ? rowsFor(scope, data) : [];
		} catch (e) { data = null; showErr(e); }
	}
	load();
	function pick(sc) { scope = sc; if (data && sc) rows = rowsFor(sc, data); }
	async function save(e) {
		e.preventDefault();
		busy = true;
		try {
			data = await api.put('/admin/shield/policies', { account_id: scope === 'global' ? null : Number(scope), rows });
			rows = rowsFor(scope, data);
			ok('shield.pol.saved');
		} catch (err) { showErr(err); } finally { busy = false; }
	}
	const label = (a) => (a ? $t('shield.pol.act.' + a) : $t('shield.pol.inherit'));
	const eff = (c, kind) => {
		if (!data) return '';
		const g = data.effective_global;
		if (c === 'script' || c === 'executable') return kind === 'u' ? g.on_unavailable_script : g.on_suspicious_script;
		if (c === 'archive') return kind === 'u' ? g.on_unavailable_script : g.on_suspicious_archive;
		return kind === 'u' ? g.on_unavailable_other : g.on_suspicious_other;
	};
</script>

<p class="small muted">{$t('shield.pol.help')}</p>
{#if data}
	<form class="card pad" onsubmit={save}>
		<label class="field"><span>{$t('shield.pol.scope')}</span>
			<select value={scope} onchange={(e) => pick(e.currentTarget.value)}>
				{#if data.can_edit_global}<option value="global">{$t('shield.pol.global')}</option>{/if}
				{#each accounts as a (a.id)}<option value={String(a.id)}>{a.username}</option>{/each}
			</select>
		</label>
		{#if scope}
			<table class="table">
				<thead><tr><th>{$t('shield.pol.class')}</th><th>{$t('shield.pol.on_unavailable')}</th><th>{$t('shield.pol.on_suspicious')}</th></tr></thead>
				<tbody>
					{#each rows as r (r.file_class)}
						<tr>
							<td>{$t('shield.pol.cls.' + r.file_class)}</td>
							<td>
								{#if r.file_class === 'archive'}<span class="small muted">{$t('shield.pol.archive_unavail')}</span>
								{:else}<select bind:value={r.on_unavailable} aria-label={$t('shield.pol.on_unavailable')}>
									{#each data.enums.on_unavailable as a}<option value={a}>{label(a)}</option>{/each}
								</select>{/if}
								<div class="small muted">{$t('shield.pol.global_is', { a: label(eff(r.file_class, 'u')) })}</div>
							</td>
							<td>
								<select bind:value={r.on_suspicious} aria-label={$t('shield.pol.on_suspicious')}>
									{#each data.enums.on_suspicious as a}<option value={a}>{label(a)}</option>{/each}
								</select>
								<div class="small muted">{$t('shield.pol.global_is', { a: label(eff(r.file_class, 's')) })}</div>
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
			<p class="small muted">{$t('shield.pol.infected_note')}{#if !data.can_edit_global} {$t('shield.pol.reseller_note')}{/if}</p>
			<button class="btn primary" disabled={busy}><Save size={15} /> {$t('common.save')}</button>
		{:else}<p class="empty">{$t('shield.pol.no_accounts')}</p>{/if}
	</form>
{/if}
