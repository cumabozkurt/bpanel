<script>
	import { Database, Plus, Trash2, KeyRound, Table2, Wand2, UserPlus, Link2, X } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t, fmt } from '$lib/i18n/index.js';
	import { showErr, ok, ask, qs } from '$lib/util.js';
	import { openTool } from '$lib/actions.js';
	import PageHead from '$lib/components/PageHead.svelte';
	import Modal from '$lib/components/Modal.svelte';
	import PasswordField from '$lib/components/PasswordField.svelte';
	import { dbUserMax, dbNameMax, dbUserSuffixProblem } from '$lib/validate.js';
	import { customValidity, maxLen } from '$lib/a11y.js';
	import { tick } from 'svelte';
	import { errText } from '$lib/util.js';

	let data = $state({ databases: [], users: [], prefix: '' });
	let dbName = $state('');
	let userName = $state('');
	let userPw = $state('');
	let grant = $state({ user_id: 0, db_id: 0, all: true, privs: [] });
	let pwOpen = $state(false);
	let cur = $state(null);
	let newPw = $state('');
	let wizOpen = $state(qs('wizard') === '1');
	let wiz = $state({ step: 1, db: '', user: '', pw: '', all: true, privs: [] });
	let wizError = $state(null);
	let grantError = $state(false);
	let uMax = $derived(dbUserMax(data.prefix));
	let nMax = $derived(dbNameMax(data.prefix));
	let busy = $state(false);
	const PRIVS = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CREATE', 'DROP', 'INDEX', 'ALTER', 'CREATE TEMPORARY TABLES', 'LOCK TABLES', 'EXECUTE', 'CREATE VIEW', 'SHOW VIEW', 'CREATE ROUTINE', 'ALTER ROUTINE', 'EVENT', 'TRIGGER', 'REFERENCES'];

	async function load() {
		try {
			data = await api.get('/user/databases');
			if (!grant.user_id && data.users[0]) grant.user_id = data.users[0].id;
			if (!grant.db_id && data.databases[0]) grant.db_id = data.databases[0].id;
		} catch (e) { showErr(e); }
	}
	load();

	async function createDB(e) {
		e.preventDefault(); busy = true;
		try { const r = await api.post('/user/databases', { name: dbName }); ok('db.created', { name: r.name }); dbName = ''; load(); } catch (err) { showErr(err); }
		busy = false;
	}
	async function createUser(e) {
		e.preventDefault(); busy = true;
		try { const r = await api.post('/user/db-users', { name: userName, password: userPw }); ok('db.user_created', { name: r.name }); userName = userPw = ''; load(); } catch (err) { showErr(err); }
		busy = false;
	}
	async function doGrant(e) {
		e.preventDefault();
		// An empty custom list used to be sent as [] which the API treats as ALL PRIVILEGES.
		if (!grant.all && !grant.privs.length) { grantError = true; document.getElementById('privs-first')?.focus(); return; }
		grantError = false;
		busy = true;
		try { await api.post('/user/db-grants', { db_id: Number(grant.db_id), user_id: Number(grant.user_id), privileges: grant.all ? ['ALL'] : grant.privs }); ok('db.granted'); load(); } catch (err) { showErr(err); }
		busy = false;
	}
	async function delDB(d) { if (!ask('db.confirm_delete', { name: d.name })) return; try { await api.del('/user/databases/' + d.id); ok('common.deleted'); load(); } catch (err) { showErr(err); } }
	async function delUser(u) { if (!ask('db.confirm_delete_user', { name: u.name })) return; try { await api.del('/user/db-users/' + u.id); ok('common.deleted'); load(); } catch (err) { showErr(err); } }
	async function revoke(dbname, uname) {
		const d = data.databases.find((x) => x.name === dbname), u = data.users.find((x) => x.name === uname);
		if (!d || !u || !ask('db.confirm_revoke', { user: uname, db: dbname })) return;
		try { await api.del(`/user/db-grants/${d.id}/${u.id}`); ok('db.revoked'); load(); } catch (err) { showErr(err); }
	}
	async function setPw(e) {
		e.preventDefault(); busy = true;
		try { await api.put(`/user/db-users/${cur.id}/password`, { password: newPw }); ok('common.saved'); pwOpen = false; } catch (err) { showErr(err); }
		busy = false;
	}
	// The wizard is all-or-nothing: POST /user/db-wizard creates the database, the user and the
	// grant in one request and the server undoes the earlier steps if a later one fails.
	async function runWizard(e) {
		e.preventDefault();
		wizError = null;
		if (wiz.step === 3 && !wiz.all && !wiz.privs.length) { wizError = { key: 'db.privs_required' }; return; }
		if (wiz.step < 4) { wiz.step++; focusStep(); return; }
		busy = true;
		try {
			const r = await api.post('/user/db-wizard', { name: wiz.db, user: wiz.user, password: wiz.pw, privileges: wiz.all ? ['ALL'] : wiz.privs });
			ok('db.wizard_done', { db: r.db.name, user: r.user.name });
			wizOpen = false; wiz = { step: 1, db: '', user: '', pw: '', all: true, privs: [] }; load();
		} catch (err) {
			const partial = err.code === 'rollback_incomplete';
			wizError = { key: partial ? 'db.wizard_partial' : 'db.wizard_rolled_back', msg: errText(err) };
			// go back to the step whose input caused the error (server sends step: db|user|grant)
			const step = err.data?.step;
			if (step === 'db') wiz.step = 1; else if (step === 'user') wiz.step = 2; else if (step === 'grant') wiz.step = 3;
			focusStep();
			load();
		}
		busy = false;
	}
	function closeWizard() { wizOpen = false; wizError = null; }
	// R2-UX-08: on every step change focus moves to the step heading ("Step 2 of 4: Create a user"),
	// which screen readers announce; Tab then reaches the step's first field.
	let stepHead = $state();
	async function focusStep() { await tick(); stepHead?.focus(); }
</script>

<PageHead title={$t('db.title')} desc={$t('db.desc')} icon={Database}>
	{#snippet actions()}
		<button class="btn" onclick={() => (wizOpen = true)}><Wand2 size={15} /> {$t('tools.db_wizard')}</button>
		<button class="btn" onclick={() => openTool({ action: 'phpmyadmin' })}><Table2 size={15} /> phpMyAdmin</button>
	{/snippet}
</PageHead>

<div class="stack">
	<div class="grid2">
		<form class="card" onsubmit={createDB}>
			<div class="card-head"><Plus size={17} /><h2>{$t('db.create_db')}</h2></div>
			<div class="card-body">
				<label class="field"><span>{$t('db.new_db')}</span><div class="input-group"><span class="addon">{data.prefix}</span><input id="db-new" bind:value={dbName} required pattern="[a-z0-9_]+" use:maxLen={nMax} data-err="errors.invalid_db_name" placeholder="wordpress" autocapitalize="off" spellcheck="false" /></div></label>
				<button class="btn primary" disabled={busy}>{$t('db.create_db')}</button>
			</div>
		</form>
		<form class="card" onsubmit={createUser}>
			<div class="card-head"><UserPlus size={17} /><h2>{$t('db.add_user')}</h2></div>
			<div class="card-body">
				<label class="field"><span>{$t('db.username')}</span><div class="input-group"><span class="addon">{data.prefix}</span><input id="dbu-new" bind:value={userName} required pattern="[a-z0-9_]+" use:maxLen={uMax} data-err="errors.invalid_db_user" autocapitalize="off" spellcheck="false" use:customValidity={dbUserSuffixProblem(userName)} /></div><small>{$t('db.user_len_help', { n: uMax })}</small></label>
				<PasswordField bind:value={userPw} id="dbpw" />
				<button class="btn primary" disabled={busy}>{$t('db.create_user')}</button>
			</div>
		</form>
	</div>

	<section class="card">
		<div class="card-head"><Database size={17} /><h2>{$t('db.current_dbs')}</h2></div>
		<div class="tw"><table class="table">
			<thead><tr><th>{$t('db.database')}</th><th>{$t('db.size')}</th><th>{$t('db.privileged_users')}</th><th><span class="sr-only">{$t('common.actions')}</span></th></tr></thead>
			<tbody>
				{#each data.databases as d}
					<tr><td><b>{d.name}</b></td><td>{$fmt.bytes(d.size_bytes)}</td>
						<td>{#each d.users ? d.users.split(',') : [] as u}<span class="badge chipx">{u} <button class="x" aria-label={$t('db.revoke_named', { user: u, db: d.name })} title={$t('db.revoke')} onclick={() => revoke(d.name, u)}><X size={11} /></button></span> {/each}</td>
						<td><div class="actions"><button class="linkbtn danger" onclick={() => delDB(d)} aria-label={$t('db.delete_db_named', { name: d.name })}><Trash2 size={13} /> {$t('common.delete')}</button></div></td></tr>
				{:else}<tr><td colspan="4" class="empty">{$t('common.none')}</td></tr>{/each}
			</tbody>
		</table></div>
	</section>

	<div class="grid2">
		<section class="card">
			<div class="card-head"><UserPlus size={17} /><h2>{$t('db.current_users')}</h2></div>
			<div class="tw"><table class="table">
				<thead><tr><th>{$t('db.username')}</th><th>{$t('db.databases')}</th><th><span class="sr-only">{$t('common.actions')}</span></th></tr></thead>
				<tbody>
					{#each data.users as u}
						<tr><td><b>{u.name}</b></td><td class="small">{u.dbs || '—'}</td>
							<td><div class="actions"><button class="linkbtn" onclick={() => { cur = u; newPw = ''; pwOpen = true; }}><KeyRound size={13} /> {$t('common.password')}</button><button class="linkbtn danger" onclick={() => delUser(u)} aria-label={$t('db.delete_user_named', { name: u.name })} title={$t('common.delete')}><Trash2 size={13} /></button></div></td></tr>
					{:else}<tr><td colspan="3" class="empty">{$t('common.none')}</td></tr>{/each}
				</tbody>
			</table></div>
		</section>
		<form class="card" onsubmit={doGrant}>
			<div class="card-head"><Link2 size={17} /><h2>{$t('db.add_user_to_db')}</h2></div>
			<div class="card-body">
				<div class="grid2">
					<label class="field"><span>{$t('db.username')}</span><select bind:value={grant.user_id}>{#each data.users as u}<option value={u.id}>{u.name}</option>{/each}</select></label>
					<label class="field"><span>{$t('db.database')}</span><select bind:value={grant.db_id}>{#each data.databases as d}<option value={d.id}>{d.name}</option>{/each}</select></label>
				</div>
				<label class="chk"><input type="checkbox" bind:checked={grant.all} onchange={() => (grantError = false)} /> <b>{$t('db.all_privileges')}</b></label>
				{#if !grant.all}
					<fieldset class="privs" aria-describedby={grantError ? 'privs-err' : undefined}>
						<legend class="sr-only">{$t('db.privileges')}</legend>
						{#each PRIVS as p, i}<label class="chk small"><input id={i === 0 ? 'privs-first' : undefined} type="checkbox" bind:group={grant.privs} value={p} onchange={() => (grantError = false)} /> {p}</label>{/each}
					</fieldset>
					{#if grantError}<p class="field-err" id="privs-err" role="alert">{$t('db.privs_required')}</p>{/if}
				{/if}
				<button class="btn primary" disabled={busy || !data.users.length || !data.databases.length || (!grant.all && !grant.privs.length)}>{$t('db.grant')}</button>
			</div>
		</form>
	</div>
</div>

<Modal bind:open={pwOpen} title={$t('db.change_password_for', { name: cur?.name })}>
	<form id="dbp" onsubmit={setPw}><PasswordField bind:value={newPw} id="dbpw2" /></form>
	{#snippet footer()}<button class="btn" onclick={() => (pwOpen = false)}>{$t('common.cancel')}</button><button class="btn primary" form="dbp" disabled={busy}>{$t('common.save')}</button>{/snippet}
</Modal>

<Modal bind:open={wizOpen} title={$t('tools.db_wizard') + ' — ' + $t('db.step', { n: wiz.step, total: 4 })} canClose={() => !busy}>
	<form id="wiz" onsubmit={runWizard}>
		<ol class="wsteps" aria-label={$t('db.wizard_steps')}>
			{#each ['db.wstep_db', 'db.wstep_user', 'db.wstep_privs', 'db.wstep_confirm'] as k, i}<li class:on={wiz.step === i + 1} class:done={wiz.step > i + 1} aria-current={wiz.step === i + 1 ? 'step' : undefined}>{$t(k)}</li>{/each}
		</ol>
		<h3 class="wstep-h" tabindex="-1" bind:this={stepHead}>{$t('db.step', { n: wiz.step, total: 4 })}: {$t(['db.wstep_db', 'db.wstep_user', 'db.wstep_privs', 'db.wstep_confirm'][wiz.step - 1])}</h3>
		{#if wizError}<div class="alert error" role="alert"><div><b>{$t(wizError.key)}</b>{#if wizError.msg}<div class="small">{wizError.msg}</div>{/if}</div></div>{/if}
		{#if wiz.step === 1}
			<label class="field"><span>{$t('db.new_db')}</span><div class="input-group"><span class="addon">{data.prefix}</span><input id="wiz-db" bind:value={wiz.db} required pattern="[a-z0-9_]+" use:maxLen={nMax} data-err="errors.invalid_db_name" autocapitalize="off" spellcheck="false" /></div></label>
		{:else if wiz.step === 2}
			<label class="field"><span>{$t('db.username')}</span><div class="input-group"><span class="addon">{data.prefix}</span><input id="wiz-user" bind:value={wiz.user} required pattern="[a-z0-9_]+" use:maxLen={uMax} data-err="errors.invalid_db_user" autocapitalize="off" spellcheck="false" use:customValidity={dbUserSuffixProblem(wiz.user)} /></div><small>{$t('db.user_len_help', { n: uMax })}</small></label>
			<PasswordField bind:value={wiz.pw} id="wizpw" />
		{:else if wiz.step === 3}
			<label class="chk"><input type="checkbox" bind:checked={wiz.all} /> <b>{$t('db.all_privileges')}</b></label>
			{#if !wiz.all}
				<fieldset class="privs"><legend class="sr-only">{$t('db.privileges')}</legend>
					{#each PRIVS as p}<label class="chk small"><input type="checkbox" bind:group={wiz.privs} value={p} /> {p}</label>{/each}</fieldset>
			{/if}
		{:else}
			<!-- R2-UX-17: the question names the privileges actually chosen -->
			<p>{wiz.all ? $t('db.wizard_confirm_all', { db: data.prefix + wiz.db, user: data.prefix + wiz.user }) : $t('db.wizard_confirm', { db: data.prefix + wiz.db, user: data.prefix + wiz.user })}</p>
			{#if !wiz.all}<ul class="privlist small" aria-label={$t('db.privileges')}>{#each wiz.privs as p}<li class="mono">{p}</li>{/each}</ul>{/if}
			<p class="muted small">{$t('db.wizard_atomic')}</p>
		{/if}
	</form>
	{#snippet footer()}
		{#if wiz.step > 1}<button class="btn" type="button" disabled={busy} onclick={() => { wiz.step--; wizError = null; focusStep(); }}>{$t('common.back')}</button>{/if}
		<button class="btn primary" form="wiz" disabled={busy}>{wiz.step < 4 ? $t('common.next') : $t('common.create')}</button>
	{/snippet}
</Modal>

<style>
	.wstep-h { font-size: 14px; margin: 0 0 10px; }
	.wstep-h:focus { outline: none; }
	.wstep-h:focus-visible { outline: 2px solid var(--primary); outline-offset: 2px; }
	.privlist { display: flex; flex-wrap: wrap; gap: 4px 10px; list-style: none; padding: 0; margin: 0 0 10px; }
	.privlist li { background: var(--card-2); border: 1px solid var(--border); border-radius: 4px; padding: 0 6px; }
	.chk { display: flex; gap: 8px; align-items: center; margin-bottom: 10px; }
	.privs { display: grid; grid-template-columns: 1fr 1fr; gap: 0 12px; margin: 0 0 10px; border: 0; padding: 0; }
	.wsteps { display: flex; gap: 6px; list-style: none; padding: 0; margin: 0 0 14px; flex-wrap: wrap; counter-reset: s; }
	.wsteps li { counter-increment: s; font-size: 12px; color: var(--muted); padding: 2px 8px; border-radius: 999px; border: 1px solid var(--border); }
	.wsteps li::before { content: counter(s) '. '; }
	.wsteps li.on { color: var(--blue-text); background: var(--blue-soft); border-color: transparent; font-weight: 600; }
	.wsteps li.done { color: var(--green-text); }
	@media (max-width: 420px) { .privs { grid-template-columns: 1fr; } }
	.chipx { gap: 2px; }
	.x { background: none; border: 0; padding: 0 0 0 2px; cursor: pointer; color: var(--muted); display: inline-flex; }
	.x:hover { color: var(--red); }
</style>
