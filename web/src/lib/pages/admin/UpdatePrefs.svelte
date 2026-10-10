<script>
	// v0.4 adminx: Update Preferences (policy in settings, status probe, apply as a job).
	import { RefreshCw } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t } from '$lib/i18n/index.js';
	import { showErr, ok, ask } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';
	let prefs = $state({ policy: 'manual', auto_reboot: 'never' });
	let st = $state(null);
	let checking = $state(false);
	async function load() { try { prefs = (await api.get('/admin/updates/prefs')).prefs; } catch (e) { showErr(e); } }
	async function check() { checking = true; try { st = await api.get('/admin/updates/status'); } catch (e) { showErr(e); } checking = false; }
	load();
	async function save(e) { e.preventDefault(); try { await api.put('/admin/updates/prefs', prefs); ok('adminx.saved'); } catch (err) { showErr(err); } }
	async function apply() {
		if (!ask('adminx.apply_confirm')) return;
		try { const r = await api.post('/admin/updates/apply'); ok('adminx.apply_started', { id: r.job_id }); } catch (e) { showErr(e); }
	}
</script>

<PageHead title={$t('tools.update_prefs')} desc={$t('adminx.upd_desc')} icon={RefreshCw} />
<form class="card" onsubmit={save}>
	<fieldset>
		<legend>{$t('adminx.policy')}</legend>
		{#each ['security', 'all', 'manual'] as p}<label class="radio"><input type="radio" bind:group={prefs.policy} value={p} /> {$t('adminx.policy_' + p)}</label>{/each}
	</fieldset>
	<fieldset>
		<legend>{$t('adminx.auto_reboot')}</legend>
		{#each ['never', 'when_required'] as p}<label class="radio"><input type="radio" bind:group={prefs.auto_reboot} value={p} /> {$t('adminx.reboot_' + p)}</label>{/each}
	</fieldset>
	<p class="muted small">{$t('adminx.policy_note')}</p>
	<button class="btn primary" type="submit">{$t('adminx.save')}</button>
</form>
<div class="card">
	<h3>{$t('adminx.status')}</h3>
	<button class="btn" onclick={check} disabled={checking}>{$t('adminx.check')}</button>
	{#if st}
		<div class="kv small">
			<div>{$t('adminx.status')}</div><div><span class="badge" class:green={st.status === 'ok'} class:amber={st.status !== 'ok'}>{$t('adminx.st_' + st.status)}</span> {st.reason ?? ''}</div>
			{#if st.status === 'ok'}
				<div>{$t('adminx.manager')}</div><div>{st.manager}</div>
				<div>{$t('adminx.upgradable')}</div><div>{st.upgradable}</div>
				<div>{$t('adminx.security')}</div><div>{st.security}</div>
				<div>{$t('adminx.reboot_required')}</div><div>{st.reboot_known ? (st.reboot_required ? $t('adminx.yes') : $t('adminx.no')) : $t('adminx.reboot_unknown')}</div>
			{/if}
		</div>
		{#if st.packages?.length}<p class="mono small">{st.packages.join(', ')}</p>{/if}
		{#if st.status === 'ok'}<button class="btn primary" onclick={apply}>{$t('adminx.apply')}</button>{/if}
	{/if}
</div>

<style>
	fieldset { border: 0; padding: 0; margin: 0 0 16px; }
	legend { font-weight: 600; font-size: 13px; margin-bottom: 6px; }
	.radio { display: inline-flex; gap: 6px; align-items: center; margin-right: 18px; }
</style>
