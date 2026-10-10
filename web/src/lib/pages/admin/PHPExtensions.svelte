<script>
	// v1.1: PHP extensions (EasyApache-like) — install or remove allowlisted extension packages per PHP version.
	import { Puzzle } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t } from '$lib/i18n/index.js';
	import { showErr, ok, ask } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';
	let versions = $state([]);
	let v = $state('');
	let data = $state(null);
	let busy = $state('');
	api.get('/admin/php').then((r) => {
		versions = (r.versions ?? r).filter((x) => x.installed).map((x) => x.version);
		v = versions[0] ?? '';
		if (v) load();
	}).catch(showErr);
	async function load() { data = null; try { data = await api.get('/admin/php/' + v + '/extensions'); } catch (e) { showErr(e); } }
	async function toggle(x) {
		if (!ask(x.installed ? 'v11.ext_remove_confirm' : 'v11.ext_install_confirm', { ext: x.name, v })) return;
		busy = x.name;
		try { await api.put('/admin/php/' + v + '/extensions/' + x.name, { install: !x.installed }); ok('v11.ext_done', { ext: x.name }); load(); } catch (e) { showErr(e); }
		busy = '';
	}
</script>

<PageHead title={$t('tools.php_extensions')} desc={$t('v11.ext_desc')} icon={Puzzle} />
<div class="stack">
	<div class="card"><div class="card-body">
		<label class="field" style="max-width:200px"><span>PHP</span><select bind:value={v} onchange={load} disabled={!versions.length}>{#each versions as x}<option value={x}>{x}</option>{/each}</select></label>
		{#if !versions.length}<p class="empty">{$t('v11.no_php')}</p>{/if}
	</div></div>
	{#if data}
		{#if data.status === 'not_installed'}<div class="card pad">{$t('v11.not_installed')} <span class="muted small">{data.reason}</span></div>{/if}
		<div class="card tw"><table class="table small">
			<thead><tr><th>{$t('v11.extension')}</th><th>{$t('v11.package')}</th><th>{$t('v11.status')}</th><th></th></tr></thead>
			<tbody>
				{#each data.extensions as x (x.name)}
					<tr><td class="mono">{x.name}</td><td class="mono">{x.package || '—'}</td>
						<td><span class="badge" class:green={x.installed}>{x.builtin ? $t('v11.builtin') : x.installed ? $t('v11.installed') : $t('v11.not_installed_short')}</span></td>
						<td class="right">{#if !x.builtin && x.package}<button class="btn sm" disabled={!!busy} onclick={() => toggle(x)}>{busy === x.name ? '…' : x.installed ? $t('v11.remove') : $t('v11.install')}</button>{/if}</td></tr>
				{/each}
			</tbody></table></div>
		<p class="muted small">{$t('v11.ext_help', { manager: data.manager || '—' })}</p>
	{/if}
</div>
