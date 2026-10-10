<script>
	import { Archive, Play, History, Loader2, Database, ShieldCheck } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t, fmt } from '$lib/i18n/index.js';
	import { showErr, ok, ask } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';
	import Modal from '$lib/components/Modal.svelte';

	let snaps = $state(null);
	let withDB = $state(true);
	let running = $state(false);
	let open = $state(false);
	let cur = $state(null);
	let rpath = $state('');
	let inPlace = $state(false);
	async function load() { try { snaps = (await api.get('/user/backups')).snapshots; } catch (e) { showErr(e); snaps = []; } }
	load();
	// v0.4: last automatic restore test of this account
	let ver = $state(undefined);
	api.get('/user/backups/verification').then((r) => (ver = r.verification)).catch(() => (ver = null));
	const verBadge = { ok: 'teal', failed: 'red', error: 'red', no_snapshot: 'gray', no_manifest: 'amber', running: 'blue' };
	async function run() {
		running = true;
		try { await api.post('/user/backups', { databases: withDB }); ok('backup.done'); load(); } catch (e) { showErr(e); }
		running = false;
	}
	function isDB(s) { return s.tags?.includes('db'); }
	function restoreDlg(s) { cur = s; rpath = isDB(s) ? 'db:' + s.tags.find((x) => x !== 'db') : ''; inPlace = false; open = true; }
	async function restore(e) {
		e.preventDefault();
		if (inPlace && !ask('backup.confirm_inplace')) return;
		try { const r = await api.post('/user/backups/restore', { snapshot: cur.id, path: rpath, in_place: inPlace }); ok('backup.restored', { to: r.restored_to }); open = false; } catch (err) { showErr(err); }
	}
</script>

<PageHead title={$t('backup.title')} desc={$t('backup.desc')} icon={Archive} />
<div class="stack">
	<section class="card card-body row" style="flex-wrap:wrap">
		<label class="row small"><input type="checkbox" bind:checked={withDB} /> {$t('backup.include_dbs')}</label>
		<span class="grow"></span>
		<button class="btn primary" onclick={run} disabled={running}>{#if running}<Loader2 size={15} class="spin" />{:else}<Play size={15} />{/if} {$t('backup.run_now')}</button>
	</section>
	{#if ver !== undefined}
		<section class="card card-body row small" style="flex-wrap:wrap" data-testid="backup-verification">
			<ShieldCheck size={16} /> <strong>{$t('backup.verify_title')}</strong>
			{#if ver}
				<span class="badge {verBadge[ver.status] ?? 'gray'}">{$t('backup.verify_' + ver.status)}</span>
				<span class="muted">{$t('backup.verify_last', { date: $fmt.date(ver.finished_at || ver.started_at), files: ver.files_checked, bad: ver.mismatches })}</span>
			{:else}
				<span class="muted">{$t('backup.verify_none')}</span>
			{/if}
		</section>
	{/if}
	<section class="card">
		<div class="card-head"><History size={17} /><h2>{$t('backup.snapshots')}</h2></div>
		<div class="tw"><table class="table">
			<thead><tr><th>{$t('backup.id')}</th><th>{$t('backup.time')}</th><th>{$t('backup.contents')}</th><th><span class="sr-only">{$t('common.actions')}</span></th></tr></thead>
			<tbody>
				{#each snaps ?? [] as s}
					<tr><td class="mono">{s.short_id}</td><td>{$fmt.date(Date.parse(s.time) / 1000)}</td>
						<td>{#if isDB(s)}<span class="badge blue"><Database size={11} /> {s.tags.find((x) => x !== 'db')}</span>{:else}<span class="badge teal">{$t('backup.files')}</span> <span class="mono small">{s.paths.join(', ')}</span>{/if}</td>
						<td><div class="actions"><button class="linkbtn" onclick={() => restoreDlg(s)} aria-label={$t('backup.restore') + ' ' + s.short_id}>{$t('backup.restore')}</button></div></td></tr>
				{:else}<tr><td colspan="4" class="empty">{snaps ? $t('backup.none') : $t('common.loading')}</td></tr>{/each}
			</tbody>
		</table></div>
	</section>
</div>

<Modal bind:open title={$t('backup.restore') + ' ' + (cur?.short_id ?? '')}>
	<form id="rst" onsubmit={restore}>
		{#if cur && isDB(cur)}
			<p>{$t('backup.restore_db', { db: rpath.slice(3) })}</p>
		{:else}
			<label class="field"><span>{$t('backup.path')}</span><div class="input-group"><span class="addon">~/</span><input bind:value={rpath} placeholder="public_html/wp-config.php" /></div><small>{$t('backup.path_help')}</small></label>
			<label class="row small"><input type="checkbox" bind:checked={inPlace} /> {$t('backup.in_place')}</label>
		{/if}
	</form>
	{#snippet footer()}<button class="btn" onclick={() => (open = false)}>{$t('common.cancel')}</button><button class="btn primary" form="rst">{$t('backup.restore')}</button>{/snippet}
</Modal>
