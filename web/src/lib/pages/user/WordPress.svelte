<script>
	import { LayoutGrid } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t } from '$lib/i18n/index.js';
	import { showErr, ok } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';
	import Installer from './Installer.svelte';

	// v0.4 appx: WordPress toolkit (free subset): list, maintenance mode, core update via WP-CLI.
	let installs = $state([]);
	let info = $state({});
	let busy = $state(false);
	let output = $state('');

	async function load() {
		try {
			installs = (await api.get('/user/installer/installs?app=wordpress')).installs;
			for (const i of installs) refresh(i);
		} catch (e) { showErr(e); }
	}
	async function refresh(i) {
		try { info[i.id] = await api.get('/user/wordpress/' + i.id); } catch (e) { info[i.id] = { error: true }; }
	}
	async function maint(i, on) {
		busy = true;
		try { info[i.id] = await api.post(`/user/wordpress/${i.id}/maintenance`, { on }); ok(on ? 'appx.maint_on' : 'appx.maint_off'); } catch (e) { showErr(e); }
		busy = false;
	}
	async function update(i) {
		busy = true;
		output = $t('appx.updating');
		try { const r = await api.post(`/user/wordpress/${i.id}/update`, {}); info[i.id] = r; output = r.output || ''; ok('appx.updated'); } catch (e) { output = ''; showErr(e); }
		busy = false;
	}
	load();
</script>

<PageHead title={$t('appx.wp_title')} desc={$t('appx.wp_desc')} icon={LayoutGrid} />
<div class="card">
	<table class="table">
		<thead><tr><th>{$t('appx.url')}</th><th>{$t('appx.version')}</th><th>{$t('appx.maintenance')}</th><th></th></tr></thead>
		<tbody>
			{#each installs as i}
				{@const x = info[i.id] || {}}
				<tr>
					<td><a href={i.url} target="_blank" rel="noopener noreferrer">{i.url}</a><br /><small class="muted">~/{i.path}</small></td>
					<td>{x.error ? $t('appx.wp_missing') : x.version || '…'}</td>
					<td>{x.maintenance ? $t('appx.on') : $t('appx.off')}</td>
					<td class="actions">
						<button class="btn sm" disabled={busy || x.error} onclick={() => maint(i, !x.maintenance)}>{x.maintenance ? $t('appx.maint_disable') : $t('appx.maint_enable')}</button>
						<button class="btn sm" disabled={busy || x.error || !x.wpcli} title={x.wpcli ? '' : $t('appx.wpcli_missing')} onclick={() => update(i)}>{$t('appx.update_core')}</button>
					</td>
				</tr>
			{:else}
				<tr><td colspan="4" class="muted">{$t('appx.no_wp')}</td></tr>
			{/each}
		</tbody>
	</table>
	<p class="small muted pad">{$t('appx.wpcli_note')}</p>
</div>
{#if output}<pre class="card pad small">{output}</pre>{/if}
<Installer only="wordpress" />
