<script>
	// v1.1: IP Functions — server addresses (persistent, bpanel-ips.service) and dedicated IPs per account.
	import { Network, Plus, Trash2 } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t } from '$lib/i18n/index.js';
	import { showErr, ok, ask, showWarnings } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';
	let data = $state(null);
	let add = $state({ ip: '', prefix: 32, dev: '' });
	let accounts = $state([]);
	let assign = $state({ id: null, ip: '' });
	async function load() {
		try {
			data = await api.get('/admin/ips');
			if (!add.dev) add.dev = data.interfaces.find((i) => i.name !== 'lo')?.name ?? '';
			const a = await api.get('/admin/accounts'); accounts = Array.isArray(a) ? a : (a.accounts ?? a.items ?? []);
		} catch (e) { showErr(e); }
	}
	async function addIP(e) {
		e.preventDefault();
		try { data = await api.post('/admin/ips', { ...add, prefix: Number(add.prefix) }); add.ip = ''; ok('v11.ip_added'); } catch (err) { showErr(err); }
	}
	async function removeIP(ifc, a) {
		if (!ask('v11.ip_remove_confirm', { ip: a.ip })) return;
		try { data = await api.post('/admin/ips/remove', { ip: a.ip, prefix: a.prefix, dev: ifc.name }); ok('v11.ip_removed'); } catch (e) { showErr(e); }
	}
	async function setAcct(e) {
		e.preventDefault();
		try { const r = await api.put('/admin/accounts/' + assign.id + '/ip', { ip: assign.ip }); showWarnings(r); ok('v11.ip_assigned', { ip: r.ip }); load(); } catch (err) { showErr(err); }
	}
	load();
</script>

<PageHead title={$t('tools.ip_functions')} desc={$t('v11.ip_desc')} icon={Network} />
{#if data}
	<div class="stack">
		<div class="card tw"><table class="table small">
			<thead><tr><th>{$t('v11.interface')}</th><th>{$t('v11.address')}</th><th>{$t('v11.scope')}</th><th></th></tr></thead>
			<tbody>
				{#each data.interfaces as ifc}
					{#each ifc.addrs as a}
						<tr><td>{ifc.name} {#if !ifc.up}<span class="badge">down</span>{/if}</td><td class="mono">{a.ip}/{a.prefix} {#if a.ip === data.server_ip}<span class="badge green">{$t('v11.main_ip')}</span>{/if}</td><td>{a.scope}</td>
							<td class="right">{#if a.managed}<button class="btn ghost sm" aria-label={$t('common.delete')} onclick={() => removeIP(ifc, a)}><Trash2 size={14} /></button>{/if}</td></tr>
					{/each}
				{/each}
			</tbody></table></div>
		<form class="card" onsubmit={addIP}><div class="card-head"><Plus size={17} /><h2>{$t('v11.ip_add')}</h2></div><div class="card-body row wraprow">
			<label class="field"><span>{$t('v11.address')}</span><input class="mono" bind:value={add.ip} required placeholder="203.0.113.10" /></label>
			<label class="field"><span>{$t('v11.prefix')}</span><input type="number" min="8" max="128" bind:value={add.prefix} /></label>
			<label class="field"><span>{$t('v11.interface')}</span><select bind:value={add.dev}>{#each data.interfaces.filter((i) => i.name !== 'lo') as i}<option value={i.name}>{i.name}</option>{/each}</select></label>
			<button class="btn primary">{$t('v11.ip_add')}</button>
		</div></form>
		<div class="card tw"><div class="card-head"><h2>{$t('v11.dedicated')}</h2></div>
			<table class="table small"><tbody>
				{#each data.assignments as a}<tr><td>{a.username}</td><td class="mono">{a.ip}</td></tr>{:else}<tr><td class="empty">{$t('v11.dedicated_none')}</td></tr>{/each}
			</tbody></table></div>
		<form class="card" onsubmit={setAcct}><div class="card-body row wraprow">
			<label class="field"><span>{$t('acc.username')}</span><select bind:value={assign.id} required>{#each accounts as a}<option value={a.id}>{a.username}</option>{/each}</select></label>
			<label class="field"><span>{$t('v11.address')}</span><input class="mono" bind:value={assign.ip} placeholder={$t('v11.shared_ip')} /></label>
			<button class="btn primary">{$t('v11.assign')}</button>
			<span class="muted small">{$t('v11.dedicated_help')}</span>
		</div></form>
	</div>
{/if}

<style>.wraprow { flex-wrap: wrap; align-items: flex-end; gap: 12px; }</style>
