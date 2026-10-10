<script>
	import { GitBranch, Download, Upload } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t } from '$lib/i18n/index.js';
	import { showErr, ok } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';

	let { params } = $props();
	let data = $state(null);
	let deployPath = $state('');
	let busy = $state('');
	let output = $state('');
	async function load() {
		try { data = await api.get(`/user/git/${params.id}`); deployPath = data.repo.deploy_path; } catch (e) { showErr(e); }
	}
	async function save(ev) {
		ev.preventDefault();
		try { await api.put(`/user/git/${params.id}`, { deploy_path: deployPath.trim() }); ok('devx.git_saved'); load(); } catch (e) { showErr(e); }
	}
	async function run(pull, deploy) {
		busy = pull ? 'pull' : 'deploy';
		try {
			const r = await api.post(`/user/git/${params.id}/deploy`, { pull, deploy });
			output = r.output || '';
			ok(r.deployed ? 'devx.git_deployed' : 'devx.git_pulled');
			load();
		} catch (e) { showErr(e); }
		busy = '';
	}
	const when = (u) => (u ? new Date(u * 1000).toLocaleString() : '—');
	load();
</script>

<PageHead title={data ? data.repo.name : $t('devx.git_title')} desc={$t('devx.git_repo_desc')} icon={GitBranch} />
{#if data}
	<div class="card pad">
		<p><strong>{$t('devx.git_path')}:</strong> <code>{data.repo.path}</code> · <strong>{$t('devx.git_current')}:</strong> {data.info.branch || '—'}</p>
		{#if data.info.last}
			<p class="small">{$t('devx.git_last')}: <code>{data.info.last.hash.slice(0, 10)}</code> {data.info.last.subject} — {data.info.last.author}, {when(data.info.last.unix)}</p>
		{:else}<p class="small muted">{$t('devx.git_no_commits')}</p>{/if}
		<div class="row gap">
			{#if data.repo.clone_url}<button class="btn" disabled={!!busy} onclick={() => run(true, !!data.repo.deploy_path)}><Download size={14} /> {$t('devx.git_pull_deploy')}</button>{/if}
			<button class="btn" disabled={!!busy || !data.repo.deploy_path} onclick={() => run(false, true)}><Upload size={14} /> {$t('devx.git_deploy_now')}</button>
		</div>
		{#if output}<pre class="small">{output}</pre>{/if}
	</div>
	<form class="card pad" onsubmit={save}>
		<label class="field"><span>{$t('devx.git_deploy_path')}</span><input bind:value={deployPath} placeholder="public_html" maxlength="255" /></label>
		<p class="small muted">{$t('devx.git_deploy_help')}</p>
		<button class="btn primary">{$t('common.save')}</button>
	</form>
	<div class="card tw">
		<table class="table">
			<thead><tr><th>{$t('devx.git_branches')}</th><th>{$t('devx.git_commit')}</th></tr></thead>
			<tbody>
				{#each data.info.branches as b (b.name + b.remote)}<tr><td>{b.name}{b.remote ? ' (' + $t('devx.git_remote') + ')' : ''}</td><td><code>{b.commit}</code></td></tr>
				{:else}<tr><td colspan="2" class="empty">{$t('devx.git_no_commits')}</td></tr>{/each}
			</tbody>
		</table>
	</div>
	<p class="small"><a href="/git">← {$t('devx.git_back')}</a></p>
{/if}
