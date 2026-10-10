<script>
	import { Layers } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t } from '$lib/i18n/index.js';
	import { showErr, ok, ask } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';

	// v0.4 appx: Application Manager (Node.js / Python) — systemd services behind an nginx proxy.
	let data = $state(null);
	let domains = $state([]);
	let busy = $state(false);
	let editing = $state(null); // null | {} (new) | app
	let form = $state({});
	let envText = $state('');
	let output = $state('');
	let states = $state({});

	async function load() {
		try {
			data = await api.get('/user/apps');
			const d = await api.get('/user/domains');
			domains = (d.domains || d || []).filter((x) => x.kind !== 'alias');
		} catch (e) { showErr(e); }
	}
	function versions(rt) {
		return (data?.runtimes || []).filter((r) => r.runtime === rt).map((r) => r.version.split('.')[0]).filter((v, i, a) => a.indexOf(v) === i);
	}
	function edit(a) {
		editing = a || {};
		form = a ? { ...a, domain_id: a.domain_id || 0 } : { name: '', runtime: 'node', version: versions('node')[0] || '', root: '', startup: 'app.js', domain_id: 0, url_path: '/' };
		envText = Object.entries(form.env || {}).map(([k, v]) => k + '=' + v).join('\n');
	}
	function parseEnv() {
		const env = {};
		for (const line of envText.split('\n')) {
			const i = line.indexOf('=');
			if (line.trim() && i > 0) env[line.slice(0, i).trim()] = line.slice(i + 1);
		}
		return env;
	}
	async function save(e) {
		e.preventDefault();
		busy = true;
		const body = { name: form.name, runtime: form.runtime, version: String(form.version), root: form.root, startup: form.startup,
			domain_id: Number(form.domain_id) || 0, url_path: form.url_path, env: parseEnv() };
		try {
			if (editing.id) await api.put('/user/apps/' + editing.id, body);
			else await api.post('/user/apps', body);
			ok('appx.saved');
			editing = null;
			load();
		} catch (err) { showErr(err); }
		busy = false;
	}
	async function ctl(a, action) {
		busy = true;
		try { states[a.id] = await api.post(`/user/apps/${a.id}/ctl`, { action }); } catch (err) { showErr(err); }
		busy = false;
	}
	async function logs(a) {
		try { output = (await api.get(`/user/apps/${a.id}/logs?lines=200`)).output || ''; } catch (err) { showErr(err); }
	}
	async function deps(a) {
		busy = true;
		output = $t('appx.deps_running');
		try { output = (await api.post(`/user/apps/${a.id}/deps`, {})).output || ''; ok('appx.deps_done'); } catch (err) { output = ''; showErr(err); }
		busy = false;
	}
	async function del(a) {
		if (!ask('appx.confirm_delete', { name: a.name })) return;
		try { await api.del('/user/apps/' + a.id); ok('common.deleted'); load(); } catch (err) { showErr(err); }
	}
	load();
</script>

<PageHead title={$t('appx.apps_title')} desc={$t('appx.apps_desc')} icon={Layers} />
{#if data}
	{#if !data.systemd}<div class="card pad warn" role="status">{$t('appx.unsupported')}</div>{/if}
	{#if data.runtimes.length === 0}<div class="card pad warn" role="status">{$t('appx.no_runtimes')}</div>{/if}
	<div class="card pad">
		<p class="small muted">{$t('appx.runtimes')}: {data.runtimes.map((r) => r.runtime + ' ' + r.version).join(', ') || '—'}</p>
		<button class="btn primary" onclick={() => edit(null)} disabled={data.runtimes.length === 0}>{$t('appx.new_app')}</button>
	</div>
	{#if editing}
		<form class="card pad" onsubmit={save}>
			<label class="field"><span>{$t('appx.name')}</span><input bind:value={form.name} disabled={!!editing.id} maxlength="32" pattern="[a-z][a-z0-9-]*" required /></label>
			<label class="field"><span>{$t('appx.runtime')}</span>
				<select bind:value={form.runtime} onchange={() => (form.version = versions(form.runtime)[0] || '')}><option value="node">Node.js</option><option value="python">Python</option><option value="ruby">Ruby</option></select></label>
			<label class="field"><span>{$t('appx.version')}</span>
				<select bind:value={form.version}>{#each versions(form.runtime) as v}<option value={v}>{v}</option>{/each}</select></label>
			<label class="field"><span>{$t('appx.root')}</span><input bind:value={form.root} placeholder="apps/myapp" required spellcheck="false" />
				<small class="muted">{$t('appx.root_help')}</small></label>
			<label class="field"><span>{$t('appx.startup')}</span><input bind:value={form.startup} placeholder={form.runtime === 'node' ? 'app.js' : form.runtime === 'ruby' ? 'app.rb' : 'app.py'} required spellcheck="false" />
				<small class="muted">{$t('appx.startup_help')}</small></label>
			<label class="field"><span>{$t('appx.domain')}</span>
				<select bind:value={form.domain_id}><option value={0}>{$t('appx.no_domain')}</option>{#each domains as d}<option value={d.id}>{d.name}</option>{/each}</select></label>
			{#if Number(form.domain_id)}
				<label class="field"><span>{$t('appx.url_path')}</span><input bind:value={form.url_path} placeholder="/" spellcheck="false" /></label>
			{/if}
			<label class="field"><span>{$t('appx.env')}</span><textarea rows="4" bind:value={envText} placeholder="KEY=value" spellcheck="false"></textarea>
				<small class="muted">{$t('appx.env_help')}</small></label>
			<button class="btn primary" disabled={busy}>{$t('common.save')}</button>
			<button type="button" class="btn" onclick={() => (editing = null)}>{$t('common.cancel')}</button>
		</form>
	{/if}
	<div class="card">
		<table class="table">
			<thead><tr><th>{$t('appx.name')}</th><th>{$t('appx.runtime')}</th><th>{$t('appx.url')}</th><th>{$t('appx.port')}</th><th>{$t('appx.state')}</th><th></th></tr></thead>
			<tbody>
				{#each data.apps as a}
					<tr>
						<td>{a.name}<br /><small class="muted">~/{a.root}/{a.startup}</small></td>
						<td>{a.runtime} {a.version}</td>
						<td>{#if a.url}<a href={a.url} target="_blank" rel="noopener noreferrer">{a.url}</a>{:else}—{/if}</td>
						<td>{a.port}</td>
						<td>{states[a.id] ? states[a.id].active + ' / ' + states[a.id].sub : '—'}</td>
						<td class="actions">
							<button class="btn sm" disabled={busy || !data.systemd} onclick={() => ctl(a, 'start')}>{$t('appx.start')}</button>
							<button class="btn sm" disabled={busy || !data.systemd} onclick={() => ctl(a, 'stop')}>{$t('appx.stop')}</button>
							<button class="btn sm" disabled={busy || !data.systemd} onclick={() => ctl(a, 'restart')}>{$t('appx.restart')}</button>
							<button class="btn sm" disabled={!data.systemd} onclick={() => logs(a)}>{$t('appx.logs')}</button>
							<button class="btn sm" disabled={busy} onclick={() => deps(a)}>{a.runtime === 'node' ? 'npm install' : a.runtime === 'ruby' ? 'bundle install' : 'pip install'}</button>
							<button class="btn sm" onclick={() => edit(a)}>{$t('common.edit')}</button>
							<button class="btn sm danger" onclick={() => del(a)}>{$t('common.delete')}</button>
						</td>
					</tr>
				{:else}
					<tr><td colspan="6" class="muted">{$t('appx.no_apps')}</td></tr>
				{/each}
			</tbody>
		</table>
	</div>
	{#if output}<pre class="card pad small" aria-label={$t('appx.output')}>{output}</pre>{/if}
{/if}
