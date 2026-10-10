<script>
	import { Truck, Search } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t } from '$lib/i18n/index.js';
	import { showErr } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';

	let res = $state(null);
	let q = $state('');
	let busy = $state(false);
	async function load(e) {
		e?.preventDefault(); busy = true;
		try { res = await api.get('/user/email/track?limit=200&q=' + encodeURIComponent(q.trim())); } catch (err) { showErr(err); }
		busy = false;
	}
	load();
	const cls = { sent: 'green', deferred: 'amber', bounced: 'red', rejected: 'red', expired: 'red' };
</script>

<PageHead title={$t('tools.track_delivery')} desc={$t('mailx.t_desc')} icon={Truck} />

<section class="card">
	<form class="bar" onsubmit={load}>
		<input bind:value={q} maxlength="100" placeholder={$t('mailx.t_search')} aria-label={$t('mailx.t_search')} />
		<button class="btn" disabled={busy}><Search size={15} /> {$t('mailx.t_run')}</button>
	</form>
	{#if res?.status === 'not_installed'}<p class="badge amber" role="status">{$t('mailx.log_not_installed')} {res.reason}</p>{/if}
	<div class="tw"><table class="table">
		<thead><tr><th>{$t('mailx.time')}</th><th>{$t('mailx.sender')}</th><th>{$t('mailx.recipient')}</th><th>{$t('mailx.state')}</th><th>{$t('mailx.relay')}</th><th>{$t('mailx.detail')}</th></tr></thead>
		<tbody>
			{#each res?.entries ?? [] as d}
				<tr>
					<td class="nowrap">{d.time}</td><td>{d.from || '<>'}</td><td>{d.to}</td>
					<td><span class="badge {cls[d.status] ?? ''}">{d.status}</span>{#if d.dsn} <small>{d.dsn}</small>{/if}</td>
					<td><small>{d.relay}</small></td><td><small>{d.detail}</small></td>
				</tr>
			{:else}<tr><td colspan="6" class="empty">{$t('common.none')}</td></tr>{/each}
		</tbody>
	</table></div>
	{#if res?.source}<small>{$t('mailx.t_source', { src: res.source, n: res.scanned })}</small>{/if}
</section>

<style>.bar { display: flex; gap: 8px; margin-bottom: 12px; } .bar input { flex: 1; } .nowrap { white-space: nowrap; }</style>
