<script>
	// v1.1: PostgreSQL web UI (phpPgAdmin equivalent) — runs SQL as the database's own role.
	import { Table2, Play } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t } from '$lib/i18n/index.js';
	import { showErr } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';
	let info = $state(null);
	let db = $state(null);
	let password = $state('');
	let sql = $state('SELECT now();');
	let tables = $state(null);
	let res = $state(null);
	let busy = $state(false);
	async function load() { try { info = await api.get('/user/postgresql/browser'); db = info.databases[0]?.id ?? null; } catch (e) { showErr(e); } }
	async function listTables() {
		busy = true;
		try { tables = await api.post('/user/postgresql/browser/tables', { database_id: db, password }); } catch (e) { showErr(e); }
		busy = false;
	}
	async function run(e) {
		e?.preventDefault(); busy = true;
		try { res = await api.post('/user/postgresql/browser/query', { database_id: db, password, sql }); } catch (err) { showErr(err); }
		busy = false;
	}
	function browse(r) { sql = `SELECT * FROM "${r[0].replaceAll('"', '""')}"."${r[1].replaceAll('"', '""')}" LIMIT 100;`; run(); }
	load();
</script>

<PageHead title={$t('tools.pg_browser')} desc={$t('v11.pg_desc')} icon={Table2} />
{#if info}
	{#if info.status === 'not_installed'}<div class="card pad"><p>{$t('v11.not_installed')} <span class="muted small">{info.reason}</span></p></div>{/if}
	<div class="stack">
		<div class="card"><div class="card-body row wraprow">
			<label class="field"><span>{$t('v11.database')}</span><select bind:value={db} disabled={!info.databases.length}>{#each info.databases as d}<option value={d.id}>{d.name}</option>{/each}</select></label>
			<label class="field"><span>{$t('v11.db_password')}</span><input type="password" bind:value={password} autocomplete="current-password" maxlength="200" /></label>
			<button class="btn" onclick={listTables} disabled={busy || !db || !password}>{$t('v11.tables')}</button>
			{#if !info.databases.length}<span class="muted small">{$t('v11.pg_none')}</span>{/if}
		</div></div>
		{#if tables}
			<div class="card tw"><table class="table small"><thead><tr><th>{$t('v11.schema')}</th><th>{$t('v11.name')}</th><th>{$t('v11.type')}</th><th></th></tr></thead>
				<tbody>{#each tables.rows as r}<tr><td>{r[0]}</td><td class="mono">{r[1]}</td><td>{r[2]}</td><td class="right"><button class="btn sm" onclick={() => browse(r)}>{$t('v11.browse')}</button></td></tr>{:else}<tr><td colspan="4" class="empty">{$t('common.none')}</td></tr>{/each}</tbody></table></div>
		{/if}
		<form class="card" onsubmit={run}><div class="card-body stack">
			<label class="field"><span>SQL</span><textarea class="mono" rows="6" bind:value={sql} spellcheck="false" maxlength="65536"></textarea></label>
			<div class="row"><button class="btn primary" disabled={busy || !db || !password}><Play size={14} /> {$t('v11.run')}</button><span class="muted small">{$t('v11.pg_help')}</span></div>
		</div></form>
		{#if res}
			<div class="card tw">
				<p class="small muted pad">{res.command ?? ''} {res.rows.length} {$t('v11.rows')} · {res.ms} ms {res.truncated ? '· ' + $t('v11.truncated_rows') : ''}</p>
				{#if res.columns.length}
					<table class="table small mono"><thead><tr>{#each res.columns as c}<th>{c}</th>{/each}</tr></thead>
						<tbody>{#each res.rows as r}<tr>{#each r as v}<td>{v}</td>{/each}</tr>{/each}</tbody></table>
				{/if}
			</div>
		{/if}
	</div>
{/if}

<style>.wraprow { flex-wrap: wrap; align-items: flex-end; gap: 12px; } .pad { padding: 8px 12px; }</style>
