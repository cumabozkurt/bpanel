<script>
	import { ShieldCheck, CheckCircle2, XCircle } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t } from '$lib/i18n/index.js';
	import { showErr } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';
	let rows = $state(null);
	api.get('/user/email/deliverability').then((r) => (rows = r ?? [])).catch(showErr);
</script>

<PageHead title={$t('tools.deliverability')} desc={$t('deliv.desc')} icon={ShieldCheck} />
<div class="card">
	<div class="tw"><table class="table">
		<thead><tr><th>{$t('domains.domain')}</th><th>MX</th><th>SPF</th><th>DKIM</th><th>DMARC</th><th><span class="sr-only">{$t('common.actions')}</span></th></tr></thead>
		<tbody>
			{#each rows ?? [] as r}
				<tr>
					<td><b>{r.domain}</b></td>
					{#each ['mx', 'spf', 'dkim', 'dmarc'] as k}
						<td>{#if r[k]}<span class="badge green"><CheckCircle2 size={12} /> {$t('deliv.valid')}</span>{:else}<span class="badge red"><XCircle size={12} /> {$t('deliv.missing')}</span>{/if}</td>
					{/each}
					<td><div class="actions"><a href={'/dns/' + r.domain}>{$t('deliv.manage_records')}</a></div></td>
				</tr>
			{:else}<tr><td colspan="6" class="empty">{rows ? $t('common.none') : $t('common.loading')}</td></tr>{/each}
		</tbody>
	</table></div>
</div>
<p class="muted small" style="margin-top:12px">{$t('deliv.note')}</p>
