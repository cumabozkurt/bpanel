<script>
	import { GitBranch, Trash2, Plus } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t } from '$lib/i18n/index.js';
	import { showErr, ok, ask } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';

	// v0.4 devx: Git Version Control (repositories under the home, run as the account).
	let repos = $state(null);
	let form = $state({ name: '', clone_url: '', path: '', branch: '', deploy_path: '' });
	let busy = $state(false);
	async function load() {
		try { repos = (await api.get('/user/git')).repos; } catch (e) { showErr(e); }
	}
	async function create(ev) {
		ev.preventDefault();
		busy = true;
		try {
			const b = { name: form.name };
			for (const k of ['clone_url', 'path', 'branch', 'deploy_path']) if (form[k].trim()) b[k] = form[k].trim();
			await api.post('/user/git', b);
			ok(b.clone_url ? 'devx.git_cloned' : 'devx.git_created');
			form = { name: '', clone_url: '', path: '', branch: '', deploy_path: '' };
			load();
		} catch (e) { showErr(e); }
		busy = false;
	}
	async function remove(g) {
		if (!ask('devx.git_delete_confirm', { name: g.name })) return;
		const files = ask('devx.git_delete_files', { path: g.path });
		try { await api.del(`/user/git/${g.id}${files ? '?files=1' : ''}`); ok('devx.git_deleted'); load(); } catch (e) { showErr(e); }
	}
	load();
</script>

<PageHead title={$t('devx.git_title')} desc={$t('devx.git_desc')} icon={GitBranch} />
<form class="card pad" onsubmit={create}>
	<h2 class="h3">{$t('devx.git_new')}</h2>
	<div class="grid2">
		<label class="field"><span>{$t('devx.git_name')}</span><input bind:value={form.name} required maxlength="64" pattern="[A-Za-z0-9][A-Za-z0-9._-]*" /></label>
		<label class="field"><span>{$t('devx.git_clone_url')}</span><input bind:value={form.clone_url} placeholder="https://… / git@host:user/repo.git" maxlength="1024" /></label>
		<label class="field"><span>{$t('devx.git_path')}</span><input bind:value={form.path} placeholder={'repositories/' + (form.name || 'name')} maxlength="255" /></label>
		<label class="field"><span>{$t('devx.git_branch')}</span><input bind:value={form.branch} placeholder="main" maxlength="100" /></label>
		<label class="field"><span>{$t('devx.git_deploy_path')}</span><input bind:value={form.deploy_path} placeholder="public_html" maxlength="255" /></label>
	</div>
	<p class="small muted">{$t('devx.git_url_help')}</p>
	<button class="btn primary" disabled={busy}><Plus size={14} /> {$t('devx.git_create')}</button>
</form>
{#if repos}
	<div class="card tw">
		<table class="table">
			<thead><tr><th>{$t('devx.git_name')}</th><th>{$t('devx.git_path')}</th><th>{$t('devx.git_clone_url')}</th><th>{$t('devx.git_deploy_path')}</th><th></th></tr></thead>
			<tbody>
				{#each repos as g (g.id)}
					<tr><td><a href={'/git/' + g.id}>{g.name}</a></td><td><code>{g.path}</code></td><td class="small">{g.clone_url || '—'}</td><td>{g.deploy_path || '—'}</td>
						<td class="right"><button class="btn ghost sm" aria-label={$t('common.delete')} onclick={() => remove(g)}><Trash2 size={14} /></button></td></tr>
				{:else}<tr><td colspan="5" class="empty">{$t('devx.git_empty')}</td></tr>{/each}
			</tbody>
		</table>
	</div>
{/if}
