<script>
	// v1.1: Change Hostname — system hostname, /etc/hosts, Postfix myhostname and the panel config.
	import { Server } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t } from '$lib/i18n/index.js';
	import { showErr, ok, ask } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';
	let host = $state('');
	let cur = $state('');
	let res = $state(null);
	api.get('/admin/server').then((s) => { cur = s.sys?.hostname ?? ''; host = cur; }).catch(showErr);
	async function save(e) {
		e.preventDefault();
		if (!ask('v11.hostname_confirm', { host })) return;
		try { res = await api.put('/admin/hostname', { hostname: host }); ok('v11.hostname_changed'); } catch (err) { showErr(err); }
	}
</script>

<PageHead title={$t('tools.change_hostname')} desc={$t('v11.hostname_desc')} icon={Server} />
<form class="card" onsubmit={save}><div class="card-body stack">
	<p class="small">{$t('v11.current')}: <span class="mono">{cur || '—'}</span></p>
	<label class="field" style="max-width:420px"><span>{$t('v11.new_hostname')}</span><input class="mono" bind:value={host} required placeholder="server.example.com" maxlength="253" /></label>
	<p class="muted small">{$t('v11.hostname_help')}</p>
	<div><button class="btn primary">{$t('common.save')}</button></div>
	{#if res}<div class="small"><p>{res.previous} → <strong>{res.hostname}</strong></p><ul class="mono">{#each res.steps as s}<li>{s}</li>{/each}</ul><p class="muted">{$t('v11.restart_required')}</p></div>{/if}
</div></form>
