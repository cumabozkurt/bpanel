<script>
	import { Code2, Download, Trash2, Loader2 } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t } from '$lib/i18n/index.js';
	import { showErr, ok, ask, showWarnings } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';
	let data = $state(null);
	let busy = $state('');
	let def = $state('');
	async function load() { try { data = await api.get('/admin/php'); def = data.default; } catch (e) { showErr(e); } }
	load();
	async function act(v, a) {
		if (a === 'remove' && !ask('aphp.confirm_remove', { v })) return;
		busy = v;
		try { await api.post(`/admin/php/${v}/${a}`); ok(a === 'install' ? 'aphp.installed' : 'aphp.removed', { v }); load(); } catch (e) { showErr(e); }
		busy = '';
	}
	async function setDefault() { try { const r = await api.put('/admin/settings', { default_php: def }); ok('common.saved'); showWarnings(r); load(); } catch (e) { showErr(e); } }
</script>

<PageHead title={$t('aphp.title')} desc={$t('aphp.desc')} icon={Code2} />
{#if data}
	<div class="card card-body row" style="margin-bottom:16px;flex-wrap:wrap">
		<label class="row"><b>{$t('aphp.system_default')}</b>
			<select bind:value={def} style="width:auto">{#each data.versions.filter((v) => v.installed) as v}<option value={v.version}>PHP {v.version}</option>{/each}</select></label>
		<button class="btn" onclick={setDefault}>{$t('common.save')}</button>
		<span class="muted small">{$t('aphp.default_help')}</span>
	</div>
	<div class="card">
		<div class="tw"><table class="table">
			<thead><tr><th>{$t('aphp.version')}</th><th>{$t('svc.status')}</th><th>{$t('svc.unit')}</th><th>{$t('aphp.sites')}</th><th><span class="sr-only">{$t('common.actions')}</span></th></tr></thead>
			<tbody>
				{#each data.versions as v}
					<tr><td><b>PHP {v.version}</b> {#if v.default}<span class="badge teal">{$t('aphp.distro_default')}</span>{/if}</td>
						<td>{#if v.installed}<span class="badge {v.running ? 'green' : 'amber'}">{v.running ? $t('svc.running') : $t('aphp.installed_state')}</span>{:else}<span class="badge">{$t('aphp.not_installed')}</span>{/if}</td>
						<td class="mono small">{v.unit}</td><td>{data.usage[v.version] ?? 0}</td>
						<td><div class="actions">
							{#if busy === v.version}<Loader2 size={16} class="spin" aria-label={$t('common.loading')} />
							{:else if v.installed}<button class="btn sm danger" disabled={!!busy || v.default} onclick={() => act(v.version, 'remove')} aria-label={$t('aphp.remove') + ' PHP ' + v.version}><Trash2 size={13} /> {$t('aphp.remove')}</button>
							{:else}<button class="btn sm outline" disabled={!!busy} onclick={() => act(v.version, 'install')} aria-label={$t('aphp.install') + ' PHP ' + v.version}><Download size={13} /> {$t('aphp.install')}</button>{/if}
						</div></td></tr>
				{/each}
			</tbody>
		</table></div>
	</div>
	<p class="muted small" style="margin-top:12px">{$t('aphp.note')}</p>
{/if}
