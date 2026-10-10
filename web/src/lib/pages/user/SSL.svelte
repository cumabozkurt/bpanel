<script>
	import { ShieldCheck, ShieldAlert, RefreshCw, Loader2 } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t, fmt } from '$lib/i18n/index.js';
	import { showErr, ok } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';

	let rows = $state(null);
	let running = $state({});
	async function load() { try { rows = await api.get('/user/ssl'); } catch (e) { showErr(e); } }
	load();
	async function run(r) {
		running[r.id] = true;
		try { await api.post('/user/ssl/autossl', { domain_id: r.id }); ok('ssl.issued', { domain: r.domain }); load(); }
		catch (e) { showErr(e); }
		running[r.id] = false;
	}
	function days(iso) { return iso ? Math.round((new Date(iso) - Date.now()) / 86400000) : null; }
</script>

<PageHead title={$t('ssl.title')} desc={$t('ssl.desc')} icon={ShieldCheck} />
<div class="card">
	<div class="tw"><table class="table">
		<thead><tr><th>{$t('domains.domain')}</th><th>{$t('ssl.status')}</th><th>{$t('ssl.issuer')}</th><th>{$t('ssl.expires')}</th><th><span class="sr-only">{$t('common.actions')}</span></th></tr></thead>
		<tbody>
			{#each rows ?? [] as r}
				{@const d = days(r.cert?.not_after)}
				<tr>
					<td><b>{r.domain}</b>{#if r.cert?.sans?.length > 1}<div class="muted small">{r.cert.sans.slice(1).join(', ')}</div>{/if}</td>
					<td>
						{#if r.cert?.present && !r.cert.self_signed && d > 0}<span class="badge green"><ShieldCheck size={12} /> {$t('ssl.valid')}</span>
						{:else if r.cert?.self_signed}<span class="badge amber"><ShieldAlert size={12} /> {$t('ssl.self_signed')}</span>
						{:else if r.status === 'failed'}<span class="badge red"><ShieldAlert size={12} /> {$t('ssl.failed')}</span>
						{:else}<span class="badge"><ShieldAlert size={12} /> {$t('ssl.none')}</span>{/if}
					</td>
					<td class="small">{r.cert?.issuer || '—'}</td>
					<td class="small">{r.cert?.not_after ? $fmt.dateISO(r.cert.not_after) + ' · ' + (d < 0 ? $t('ssl.expired_days', { n: -d }) : $t('ssl.days_left', { n: d })) : '—'}</td>
					<td><div class="actions"><button class="btn sm outline" disabled={running[r.id]} onclick={() => run(r)} aria-label={(r.cert?.present ? $t('ssl.renew') : $t('ssl.run_autossl')) + ': ' + r.domain}>
						{#if running[r.id]}<Loader2 size={14} class="spin" />{:else}<RefreshCw size={14} />{/if} {r.cert?.present ? $t('ssl.renew') : $t('ssl.run_autossl')}</button></div></td>
				</tr>
			{:else}<tr><td colspan="5" class="empty">{rows ? $t('common.none') : $t('common.loading')}</td></tr>{/each}
		</tbody>
	</table></div>
</div>
<p class="muted small" style="margin-top:12px">{$t('ssl.note')}</p>
