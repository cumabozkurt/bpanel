<script>
	import { Activity, RefreshCw, XCircle } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t } from '$lib/i18n/index.js';
	import { showErr, ok, ask } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';

	let res = $state(null);
	let busy = $state(false);
	async function load() {
		busy = true;
		try { res = await api.get('/user/databases/processes'); } catch (err) { showErr(err); }
		busy = false;
	}
	async function kill(p) {
		if (!ask('dbx.confirm_kill', { id: p.id })) return;
		try { await api.post('/user/databases/processes/kill', { engine: p.engine, id: p.id }); ok('dbx.killed'); load(); } catch (err) { showErr(err); }
	}
	load();
</script>

<PageHead title={$t('tools.db_processes')} desc={$t('dbx.proc_desc')} icon={Activity} />

<section class="card">
	<div class="bar">
		<button class="btn" onclick={load} disabled={busy}><RefreshCw size={15} /> {$t('dbx.refresh')}</button>
		{#if res}
			<span class="badge {res.mariadb.status === 'ok' ? 'green' : 'amber'}">MariaDB: {$t('dbx.engine_' + res.mariadb.status)}</span>
			<span class="badge {res.postgresql.status === 'ok' ? 'green' : ''}">PostgreSQL: {$t('dbx.engine_' + res.postgresql.status)}</span>
		{/if}
	</div>
	<div class="tw"><table class="table">
		<thead><tr><th>{$t('dbx.engine')}</th><th>ID</th><th>{$t('dbx.user')}</th><th>{$t('dbx.db')}</th><th>{$t('dbx.state')}</th><th>{$t('dbx.seconds')}</th><th>{$t('dbx.query')}</th><th>{$t('common.actions')}</th></tr></thead>
		<tbody>
			{#each res?.processes ?? [] as p}
				<tr><td>{p.engine}</td><td>{p.id}</td><td>{p.user}</td><td>{p.db}</td><td><small>{p.command} {p.state}</small></td>
					<td class={p.seconds > 30 ? 'warn' : ''}>{p.seconds}</td><td><code class="q">{p.query}</code></td>
					<td><button class="btn ghost" onclick={() => kill(p)} aria-label={$t('dbx.kill')}><XCircle size={15} /></button></td></tr>
			{:else}<tr><td colspan="8" class="empty">{$t('dbx.no_queries')}</td></tr>{/each}
		</tbody>
	</table></div>
</section>

<style>.bar { display: flex; gap: 8px; margin-bottom: 12px; align-items: center; flex-wrap: wrap; } .q { white-space: pre-wrap; word-break: break-all; font-size: 12px; } .warn { color: var(--amber, #b45309); font-weight: 600; }</style>
