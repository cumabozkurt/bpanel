<script>
	import { ShieldAlert, Trash2, Plus } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t } from '$lib/i18n/index.js';
	import { showErr, ok, ask } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';

	// v0.4 usagex: cPHulk-like page over fail2ban (separate GPL process) + netsec temporary blocks.
	let data = $state(null);
	let allow = $state({ ip: '', note: '' });
	async function load() {
		try { data = await api.get('/admin/brute-force'); } catch (e) { showErr(e); }
	}
	async function unban(jail, ip) {
		try { await api.post('/admin/brute-force/unban', { jail, ip }); ok('usagex.bf_unbanned', { ip }); load(); } catch (e) { showErr(e); }
	}
	async function delBlock(b) {
		try { await api.del(`/admin/firewall/blocks/${b.id}`); ok('usagex.bf_unbanned', { ip: b.ip }); load(); } catch (e) { showErr(e); }
	}
	async function addAllow(e) {
		e.preventDefault();
		try {
			const r = await api.post('/admin/brute-force/allowlist', { ip: allow.ip.trim(), note: allow.note });
			ok(r.fail2ban === 'done' ? 'usagex.bf_allowed' : 'usagex.bf_allowed_db', { ip: r.ip });
			allow = { ip: '', note: '' }; load();
		} catch (err) { showErr(err); }
	}
	async function delAllow(a) {
		if (!ask('usagex.bf_allow_del_q', { ip: a.ip })) return;
		try { await api.del(`/admin/brute-force/allowlist/${a.id}`); load(); } catch (e) { showErr(e); }
	}
	const when = (u) => (u ? new Date(u * 1000).toLocaleString() : '—');
	load();
</script>

<PageHead title={$t('usagex.bf_title')} desc={$t('usagex.bf_desc')} icon={ShieldAlert} />
{#if data}
	{#if data.fail2ban.status !== 'ok'}
		<div class="card pad warn" role="status">{$t('usagex.bf_f2b.' + (['not_installed', 'not_running'].includes(data.fail2ban.status) ? data.fail2ban.status : 'unsupported'))}</div>
	{/if}
	<h2 class="h3">{$t('usagex.bf_jails')}</h2>
	<div class="card tw">
		<table class="table">
			<thead><tr><th>{$t('usagex.bf_jail')}</th><th class="right">{$t('usagex.bf_failed')}</th><th class="right">{$t('usagex.bf_banned')}</th><th class="right">{$t('usagex.bf_total')}</th><th>{$t('usagex.bf_ips')}</th></tr></thead>
			<tbody>
				{#each data.fail2ban.jails as j (j.name)}
					<tr><td>{j.name}</td><td class="right">{j.currently_failed}</td><td class="right">{j.currently_banned}</td><td class="right">{j.total_banned}</td>
						<td>{#each j.banned as ip}<span class="chip"><code>{ip}</code> <button class="btn ghost sm" onclick={() => unban(j.name, ip)}>{$t('usagex.bf_unban')}</button></span> {:else}—{/each}</td></tr>
				{:else}<tr><td colspan="5" class="empty">{$t('usagex.bf_no_jails')}</td></tr>{/each}
			</tbody>
		</table>
	</div>
	<h2 class="h3">{$t('usagex.bf_blocks')}</h2>
	<div class="card tw">
		<table class="table">
			<thead><tr><th>IP</th><th>{$t('netsec.reason')}</th><th>{$t('netsec.source')}</th><th>{$t('netsec.expires')}</th><th></th></tr></thead>
			<tbody>
				{#each data.blocks as b (b.id)}
					<tr><td><code>{b.ip}</code></td><td>{b.reason}</td><td>{b.source}</td><td>{when(b.expires_at)}</td><td class="right"><button class="btn ghost sm" onclick={() => delBlock(b)}>{$t('usagex.bf_unban')}</button></td></tr>
				{:else}<tr><td colspan="5" class="empty">{$t('usagex.bf_no_blocks')}</td></tr>{/each}
			</tbody>
		</table>
	</div>
	<h2 class="h3">{$t('usagex.bf_allowlist')}</h2>
	<form class="card pad row" onsubmit={addAllow}>
		<label class="field"><span>IP / CIDR</span><input bind:value={allow.ip} required maxlength="64" /></label>
		<label class="field"><span>{$t('usagex.bf_note')}</span><input bind:value={allow.note} maxlength="200" /></label>
		<button class="btn primary"><Plus size={15} /> {$t('usagex.bf_allow_add')}</button>
	</form>
	<div class="card tw">
		<table class="table">
			<thead><tr><th>IP / CIDR</th><th>{$t('usagex.bf_note')}</th><th>{$t('usagex.bf_added')}</th><th></th></tr></thead>
			<tbody>
				{#each data.allowlist as a (a.id)}
					<tr><td><code>{a.ip}</code></td><td>{a.note}</td><td>{when(a.created_at)}</td><td class="right"><button class="btn ghost sm" aria-label={$t('common.delete')} onclick={() => delAllow(a)}><Trash2 size={14} /></button></td></tr>
				{:else}<tr><td colspan="4" class="empty">{$t('usagex.bf_allow_empty')}</td></tr>{/each}
			</tbody>
		</table>
	</div>
	<p class="small muted">{$t('usagex.bf_help')}</p>
{/if}
