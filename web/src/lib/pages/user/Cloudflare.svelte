<script>
	// v1.1: Cloudflare (optional) — detects domains on Cloudflare; with your own API token, copies missing DNS records.
	import { Cloud, Link, Unlink, RefreshCw } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t } from '$lib/i18n/index.js';
	import { showErr, ok, ask } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';
	let data = $state(null);
	let token = $state('');
	let plan = $state(null);
	let busy = $state(false);
	async function load() { try { data = await api.get('/user/cloudflare'); } catch (e) { showErr(e); } }
	async function link(e) {
		e.preventDefault(); busy = true;
		try { data = await api.put('/user/cloudflare', { token }); token = ''; ok('v11.cf_linked'); } catch (err) { showErr(err); }
		busy = false;
	}
	async function unlink() {
		if (!ask('v11.cf_unlink_confirm')) return;
		try { data = await api.del('/user/cloudflare'); ok('v11.cf_unlinked'); } catch (e) { showErr(e); }
	}
	async function sync(d, dry) {
		busy = true;
		try {
			const r = await api.post('/user/cloudflare/sync', { domain_id: d.id, dry_run: dry });
			if (dry) plan = { domain: d, missing: r.missing };
			else { plan = null; ok('v11.cf_synced', { n: r.created }); }
		} catch (e) { showErr(e); }
		busy = false;
	}
	load();
</script>

<PageHead title={$t('tools.cloudflare')} desc={$t('v11.cf_desc')} icon={Cloud} />
{#if data}
	<div class="stack">
		{#if data.linked}
			<div class="card pad row"><span class="badge green">{$t('v11.cf_linked_badge')}</span> {#if data.error}<span class="muted small">{data.error}</span>{/if}
				<button class="btn sm" onclick={unlink}><Unlink size={14} /> {$t('v11.cf_unlink')}</button></div>
		{:else}
			<form class="card" onsubmit={link}><div class="card-body stack">
				<label class="field"><span>{$t('v11.cf_token')}</span><input type="password" bind:value={token} required minlength="20" maxlength="200" autocomplete="off" /><small>{$t('v11.cf_token_help')}</small></label>
				<div><button class="btn primary" disabled={busy}><Link size={14} /> {$t('v11.cf_link')}</button></div>
			</div></form>
		{/if}
		<div class="card tw"><table class="table">
			<thead><tr><th>{$t('acc.domain')}</th><th>{$t('v11.cf_on')}</th><th>NS</th><th>{$t('v11.cf_in_account')}</th><th></th></tr></thead>
			<tbody>
				{#each data.domains as d (d.id)}
					<tr><td>{d.domain}</td><td><span class="badge" class:green={d.on_cloudflare}>{d.on_cloudflare ? $t('adminx.yes') : $t('adminx.no')}</span></td>
						<td class="mono small">{d.nameservers.join(', ') || '—'}</td><td>{data.linked ? (d.in_account ? (d.zone_status || $t('adminx.yes')) + (d.plan ? ' · ' + d.plan : '') : $t('adminx.no')) : '—'}</td>
						<td class="right">{#if data.linked && d.in_account}<button class="btn sm" disabled={busy} onclick={() => sync(d, true)}><RefreshCw size={14} /> {$t('v11.cf_compare')}</button>{/if}</td></tr>
				{:else}<tr><td colspan="5" class="empty">{$t('webx.no_domains')}</td></tr>{/each}
			</tbody></table></div>
		{#if plan}
			<div class="card pad">
				<p>{$t('v11.cf_missing', { n: plan.missing.length, domain: plan.domain.domain })}</p>
				<ul class="mono small">{#each plan.missing as r}<li>{r.type} {r.name} {r.content}</li>{/each}</ul>
				{#if plan.missing.length}<button class="btn primary" disabled={busy} onclick={() => sync(plan.domain, false)}>{$t('v11.cf_create')}</button>{/if}
			</div>
		{/if}
		<p class="muted small">{$t('v11.cf_note')}</p>
	</div>
{/if}
