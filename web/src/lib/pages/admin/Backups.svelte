<script>
	// v0.4 backup part B: per-account restore verification + scheduled
	// backup/retention status, "Verify now", and the backup policy.
	import { Archive } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t, fmt } from '$lib/i18n/index.js';
	import { showErr } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';
	let rows = $state([]);
	let pol = $state(null);
	let busy = $state({});
	let saving = $state(false);
	let saved = $state(false);
	async function load() {
		try { const r = await api.get('/admin/backups/overview'); rows = r.accounts; pol ??= r.policy; } catch (e) { showErr(e); }
	}
	load();
	async function verify(a) {
		busy = { ...busy, [a.account_id]: true };
		try { await api.post('/admin/accounts/' + a.account_id + '/backups/verify'); } catch (e) { showErr(e); }
		busy = { ...busy, [a.account_id]: false };
		load();
	}
	async function save(e) {
		e.preventDefault();
		saving = true; saved = false;
		const n = (v) => Number(v) || 0;
		try {
			pol = await api.put('/admin/backups/policy', { auto: !!pol.auto, databases: !!pol.databases, interval_hours: n(pol.interval_hours),
				keep_last: n(pol.keep_last), keep_daily: n(pol.keep_daily), keep_weekly: n(pol.keep_weekly), keep_monthly: n(pol.keep_monthly), keep_yearly: n(pol.keep_yearly) });
			saved = true;
		} catch (err) { showErr(err); }
		saving = false;
	}
	const vClass = (s) => (s === 'ok' ? 'green' : s === 'failed' || s === 'error' ? 'red' : 'amber');
</script>

<PageHead title={$t('backup.admin_title')} desc={$t('backup.admin_desc')} icon={Archive} />

{#if pol}
	<form class="card" onsubmit={save}>
		<h3>{$t('backup.policy_title')}</h3>
		<label class="check"><input type="checkbox" bind:checked={pol.auto} /> {$t('backup.policy_auto')}</label>
		<label class="check"><input type="checkbox" bind:checked={pol.databases} /> {$t('backup.include_dbs')}</label>
		<div class="grid">
			<label>{$t('backup.policy_interval')}<input type="number" min="1" max="744" bind:value={pol.interval_hours} /></label>
			<label>{$t('backup.keep_last')}<input type="number" min="0" max="1000" bind:value={pol.keep_last} /></label>
			<label>{$t('backup.keep_daily')}<input type="number" min="0" max="1000" bind:value={pol.keep_daily} /></label>
			<label>{$t('backup.keep_weekly')}<input type="number" min="0" max="1000" bind:value={pol.keep_weekly} /></label>
			<label>{$t('backup.keep_monthly')}<input type="number" min="0" max="1000" bind:value={pol.keep_monthly} /></label>
			<label>{$t('backup.keep_yearly')}<input type="number" min="0" max="1000" bind:value={pol.keep_yearly} /></label>
		</div>
		<p class="small muted">{$t('backup.policy_hint')}</p>
		<button class="btn" type="submit" disabled={saving}>{$t('backup.policy_save')}</button>
		{#if saved}<span class="small">{$t('backup.policy_saved')}</span>{/if}
	</form>
{/if}

<div class="card">
	<div class="tw"><table class="table">
		<thead><tr><th>{$t('backup.col_account')}</th><th>{$t('backup.verify_title')}</th><th>{$t('backup.col_checked')}</th><th>{$t('backup.col_files')}</th><th>{$t('backup.col_mismatches')}</th><th>{$t('backup.col_last_run')}</th><th>{$t('backup.col_retention')}</th><th></th></tr></thead>
		<tbody>
			{#each rows as a}
				<tr>
					<td>{a.username}</td>
					<td>{#if a.verification}<span class="badge {vClass(a.verification.status)}" title={a.verification.error}>{$t('backup.verify_' + a.verification.status)}</span>{:else}<span class="muted">—</span>{/if}</td>
					<td class="small">{a.verification ? $fmt.date(a.verification.finished_at || a.verification.started_at) : '—'}</td>
					<td>{a.verification ? a.verification.files_checked : '—'}</td>
					<td>{a.verification ? a.verification.mismatches : '—'}</td>
					<td class="small">{#if a.last_run}<span class="badge {a.last_run.status === 'ok' ? 'green' : a.last_run.status === 'failed' ? 'red' : 'amber'}" title={a.last_run.error}>{$t('backup.run_' + a.last_run.status)}</span> {$fmt.date(a.last_run.started_at)}{:else}—{/if}</td>
					<td class="small">{#if a.last_run?.retention_status}<span title={a.last_run.retention_error}>{$t('backup.ret_' + a.last_run.retention_status)}</span>{#if a.last_run.retention_status === 'ok'} ({$t('backup.ret_removed', { n: a.last_run.removed })}){/if}{:else}—{/if}</td>
					<td><button class="btn sm" disabled={busy[a.account_id]} onclick={() => verify(a)}>{busy[a.account_id] ? $t('backup.verify_running') : $t('backup.verify_now')}</button></td>
				</tr>
			{:else}
				<tr><td colspan="8" class="muted">{$t('backup.admin_empty')}</td></tr>
			{/each}
		</tbody>
	</table></div>
</div>
