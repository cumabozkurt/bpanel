<script>
	import { ArrowRightLeft } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t } from '$lib/i18n/index.js';
	import { showErr, ok, ask, errText } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';

	// v0.4 xfer: source → analyse/preview → conflicts → import job → report
	const steps = ['source', 'analyse', 'conflicts', 'import', 'report'];
	let step = $state('source');
	let mode = $state('local');
	let list = $state({ archives: [], dir: '' });
	let archive = $state('');
	let remote = $state({ host: '', port: 22, user: 'root', remote_path: '', auth: 'key', secret: '', allow_private: false });
	let analysis = $state(null);
	let packages = $state([]);
	let opts = $state({ package_id: 0, skip_dns: false, skip_home: false, skip_databases: false, skip_mail: false });
	let job = $state(null);
	let report = $state(null);
	let busy = $state(false);
	let history = $state([]);
	let accounts = $state([]);
	let exportAcc = $state('');

	function size(n) {
		if (!n) return '0 B';
		const u = ['B', 'KB', 'MB', 'GB', 'TB'];
		let i = 0;
		while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
		return n.toFixed(i ? 1 : 0) + ' ' + u[i];
	}
	async function load() {
		try { list = await api.get('/admin/xfer/archives'); } catch (err) { showErr(err); }
		try { history = (await api.get('/admin/xfer/imports')).runs; } catch (err) { /* optional */ }
	}
	async function loadAux() {
		try { const p = await api.get('/admin/packages'); packages = Array.isArray(p) ? p : (p.packages ?? p.items ?? []); } catch (err) { /* optional */ }
		try { const a = await api.get('/admin/accounts'); accounts = Array.isArray(a) ? a : (a.accounts ?? a.items ?? []); } catch (err) { /* optional */ }
	}
	async function waitJob(id) {
		for (;;) {
			const j = await api.get('/jobs/' + id);
			job = j;
			if (j.status === 'succeeded' || j.status === 'failed') return j;
			await new Promise((r) => setTimeout(r, 1500));
		}
	}
	async function analyse(name) {
		archive = name;
		busy = true;
		try {
			analysis = await api.post('/admin/xfer/analyse', { archive: name });
			step = 'analyse';
		} catch (err) { showErr(err); } finally { busy = false; }
	}
	async function pull(e) {
		e.preventDefault();
		busy = true;
		try {
			const r = await api.post('/admin/xfer/fetch', { ...remote, port: Number(remote.port) });
			remote.secret = '';
			const j = await waitJob(r.job_id);
			if (j.status === 'failed') { showErr({ code: j.error }); return; }
			await load();
			await analyse(r.archive);
		} catch (err) { showErr(err); } finally { busy = false; job = null; }
	}
	async function startImport() {
		busy = true;
		step = 'import';
		try {
			const r = await api.post('/admin/xfer/import', { archive, ...opts, package_id: Number(opts.package_id) });
			const j = await waitJob(r.job_id);
			report = j.result ?? null;
			if (!report) {
				const h = (await api.get('/admin/xfer/imports')).runs.find((x) => x.job_id === r.job_id);
				report = h?.report ?? null;
			}
			step = 'report';
			load();
		} catch (err) { showErr(err); step = 'conflicts'; } finally { busy = false; }
	}
	async function del(name) {
		if (!(await ask('xfer.delete_confirm', { name }))) return;
		try { await api.del('/admin/xfer/archives/' + encodeURIComponent(name)); load(); } catch (err) { showErr(err); }
	}
	async function doExport(e) {
		e.preventDefault();
		if (!exportAcc) return;
		try { await api.post('/admin/accounts/' + exportAcc + '/export', {}); ok('xfer.export_started'); load(); } catch (err) { showErr(err); }
	}
	function reset() { step = 'source'; analysis = null; report = null; archive = ''; job = null; }
	const badge = (s) => ({ ok: 'green', failed: 'red', skipped: 'gray', action_required: 'amber', done: 'green', running: 'amber', queued: 'gray' })[s] ?? 'gray';
	load();
	loadAux();
</script>

<PageHead title={$t('tools.transfer_tool')} desc={$t('xfer.desc')} icon={ArrowRightLeft} />

<ol class="steps" aria-label={$t('tools.transfer_tool')}>
	{#each steps as s, i}<li class:cur={s === step} class:done={steps.indexOf(step) > i}>{$t('xfer.step_' + s)}</li>{/each}
</ol>

{#if step === 'source'}
<section class="card">
	<div class="bar" role="radiogroup">
		<label><input type="radio" bind:group={mode} value="local" /> {$t('xfer.src_local')}</label>
		<label><input type="radio" bind:group={mode} value="remote" /> {$t('xfer.src_remote')}</label>
	</div>
	{#if mode === 'local'}
		<p><small>{$t('xfer.local_hint', { dir: list.dir })}</small> <button class="btn ghost" onclick={load}>{$t('xfer.refresh')}</button></p>
		{#if !list.archives?.length}<p>{$t('xfer.no_archives')}</p>{:else}
		<table>
			<thead><tr><th>{$t('xfer.step_source')}</th><th>{$t('xfer.home')}</th><th></th></tr></thead>
			<tbody>
			{#each list.archives as a}
				<tr><td><code>{a.name}</code></td><td>{size(a.bytes)}</td>
					<td class="actions"><button class="btn" disabled={busy} onclick={() => analyse(a.name)}>{$t('xfer.analyse')}</button>
					<button class="btn ghost" onclick={() => del(a.name)}>{$t('common.delete')}</button></td></tr>
			{/each}
			</tbody>
		</table>{/if}
	{:else}
		<form class="grid" onsubmit={pull}>
			<label>{$t('xfer.host')}<input required bind:value={remote.host} autocomplete="off" /></label>
			<label>{$t('xfer.port')}<input type="number" min="1" max="65535" bind:value={remote.port} /></label>
			<label>{$t('xfer.user')}<input required bind:value={remote.user} autocomplete="off" /></label>
			<label>{$t('xfer.remote_path')}<input required bind:value={remote.remote_path} placeholder="/home/cpmove-user.tar.gz" /></label>
			<label>{$t('xfer.auth')}<select bind:value={remote.auth}><option value="key">{$t('xfer.auth_key')}</option><option value="password">{$t('xfer.auth_password')}</option></select></label>
			{#if remote.auth === 'key'}
				<label class="wide">{$t('xfer.secret_key')}<textarea rows="5" required bind:value={remote.secret} autocomplete="off" spellcheck="false"></textarea></label>
			{:else}
				<label>{$t('xfer.secret_password')}<input type="password" required bind:value={remote.secret} autocomplete="new-password" /></label>
			{/if}
			<label class="row wide"><input type="checkbox" bind:checked={remote.allow_private} /> {$t('xfer.allow_private')}</label>
			<p class="wide"><small>{$t('xfer.secret_note')}</small></p>
			<button class="btn" disabled={busy}>{busy ? $t('xfer.pulling') : $t('xfer.pull')}</button>
		</form>
	{/if}
</section>
<section class="card">
	<h3>{$t('xfer.export')}</h3>
	<form class="bar" onsubmit={doExport}>
		<select bind:value={exportAcc} aria-label={$t('xfer.account')}>
			<option value="">{$t('xfer.account')}</option>
			{#each accounts.filter((a) => (a.role ?? 'user') === 'user') as a}<option value={String(a.id)}>{a.username}</option>{/each}
		</select>
		<button class="btn" disabled={!exportAcc}>{$t('xfer.export')}</button>
	</form>
	<p><small>{$t('xfer.export_hint')}</small></p>
</section>
{/if}

{#if step === 'analyse' && analysis}
{@const m = analysis.model}
<section class="card">
	<dl class="kv">
		<dt>{$t('xfer.format')}</dt><dd>{m.format}</dd>
		<dt>{$t('xfer.account')}</dt><dd>{m.account.username}{m.account.email ? ' · ' + m.account.email : ''}</dd>
		<dt>{$t('xfer.main_domain')}</dt><dd>{m.account.main_domain}</dd>
		<dt>{$t('xfer.domains')}</dt><dd>{m.domains.map((d) => d.name + ' (' + d.kind + ')').join(', ')}</dd>
		<dt>{$t('xfer.databases')}</dt><dd>{m.databases.map((d) => d.name).join(', ') || '—'}</dd>
		<dt>{$t('xfer.zones')}</dt><dd>{m.zones.map((z) => z.domain).join(', ') || '—'}</dd>
		<dt>{$t('xfer.mailboxes')}</dt><dd>{m.mailboxes.map((x) => x.address).join(', ') || '—'}</dd>
		<dt>{$t('xfer.forwarders')}</dt><dd>{m.forwarders.length}</dd>
		<dt>{$t('xfer.home')}</dt><dd>{$t('xfer.files_bytes', { files: m.home.files, size: size(m.home.bytes) })}</dd>
	</dl>
	{#if m.unsupported.length}<h4>{$t('xfer.unsupported')}</h4><ul>{#each m.unsupported as u}<li><code>{u.part}</code> — {u.reason}</li>{/each}</ul>{/if}
	{#if m.warnings.length}<h4>{$t('xfer.warnings')}</h4><ul>{#each m.warnings as w}<li>{w}</li>{/each}</ul>{/if}
	<div class="bar"><button class="btn ghost" onclick={reset}>{$t('xfer.back')}</button><button class="btn" onclick={() => (step = 'conflicts')}>{$t('xfer.next')}</button></div>
</section>
{/if}

{#if step === 'conflicts' && analysis}
<section class="card">
	{#if analysis.conflicts.length}
		<p>{$t('xfer.conflicts_help')}</p>
		<ul>{#each analysis.conflicts as c}<li><span class="badge red">{$t('xfer.conflict_' + c.kind)}</span> <code>{c.value}</code></li>{/each}</ul>
		<div class="bar"><button class="btn ghost" onclick={() => (step = 'analyse')}>{$t('xfer.back')}</button><button class="btn" onclick={() => analyse(archive)}>{$t('xfer.refresh')}</button></div>
	{:else}
		<p><span class="badge green">✓</span> {$t('xfer.no_conflicts')}</p>
		<div class="grid">
			<label>{$t('xfer.package')}<select bind:value={opts.package_id}><option value={0}>{$t('xfer.package_auto')}</option>{#each packages as p}<option value={p.id}>{p.name}</option>{/each}</select></label>
			<label class="row"><input type="checkbox" bind:checked={opts.skip_dns} /> {$t('xfer.skip_dns')}</label>
			<label class="row"><input type="checkbox" bind:checked={opts.skip_home} /> {$t('xfer.skip_home')}</label>
			<label class="row"><input type="checkbox" bind:checked={opts.skip_databases} /> {$t('xfer.skip_databases')}</label>
			<label class="row"><input type="checkbox" bind:checked={opts.skip_mail} /> {$t('xfer.skip_mail')}</label>
		</div>
		<div class="bar"><button class="btn ghost" onclick={() => (step = 'analyse')}>{$t('xfer.back')}</button><button class="btn" disabled={busy} onclick={startImport}>{$t('xfer.start_import')}</button></div>
	{/if}
</section>
{/if}

{#if step === 'import'}
<section class="card" aria-live="polite"><p>{$t('xfer.job_running')} {job?.status ?? ''}</p></section>
{/if}

{#if step === 'report'}
<section class="card">
	{#if job?.status === 'failed'}<p class="err">{$t('xfer.job_failed', { error: errText({ code: job.error }) })}</p>{/if}
	{#if report?.steps}
	<table>
		<thead><tr><th>{$t('xfer.step_import')}</th><th></th><th>{$t('xfer.status')}</th><th></th></tr></thead>
		<tbody>{#each report.steps as s}<tr><td>{s.part}</td><td><code>{s.item ?? ''}</code></td><td><span class="badge {badge(s.status)}">{$t('xfer.st_' + s.status)}</span></td><td><small>{s.detail ?? ''}</small></td></tr>{/each}</tbody>
	</table>
	{#if report.conflicts?.length}<ul>{#each report.conflicts as c}<li><span class="badge red">{$t('xfer.conflict_' + c.kind)}</span> <code>{c.value}</code></li>{/each}</ul>{/if}
	{#if report.unsupported?.length}<h4>{$t('xfer.unsupported')}</h4><ul>{#each report.unsupported as u}<li><code>{u.part}</code> — {u.reason}</li>{/each}</ul>{/if}
	{/if}
	<button class="btn" onclick={reset}>{$t('xfer.new_import')}</button>
</section>
{/if}

{#if history.length}
<section class="card">
	<h3>{$t('xfer.history')}</h3>
	<table>
		<thead><tr><th>{$t('xfer.when')}</th><th></th><th>{$t('xfer.account')}</th><th>{$t('xfer.format')}</th><th>{$t('xfer.status')}</th></tr></thead>
		<tbody>{#each history as h}<tr><td>{new Date(h.created_at * 1000).toLocaleString()}</td><td>{$t('xfer.kind_' + h.kind)} <code>{h.archive}</code></td><td>{h.username}</td><td>{h.format}</td><td><span class="badge {badge(h.status)}">{h.status}</span></td></tr>{/each}</tbody>
	</table>
</section>
{/if}

<style>
	.steps { display: flex; gap: 6px; list-style: none; padding: 0; flex-wrap: wrap; }
	.steps li { padding: 4px 10px; border-radius: 999px; border: 1px solid var(--border, #ccc); font-size: .85em; }
	.steps li.cur { font-weight: 600; border-color: currentColor; }
	.steps li.done { opacity: .7; }
	.bar { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin-top: 8px; }
	.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 10px; align-items: end; }
	.grid label { display: flex; flex-direction: column; gap: 4px; }
	.grid .wide { grid-column: 1 / -1; }
	.row { display: flex !important; flex-direction: row !important; gap: 8px; align-items: center; }
	.kv { display: grid; grid-template-columns: max-content 1fr; gap: 4px 16px; }
	.kv dt { font-weight: 600; }
	.actions { display: flex; gap: 6px; }
	.err { color: var(--red, #b00020); }
</style>
