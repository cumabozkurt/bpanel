<script>
	import { Network, ChevronRight } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t } from '$lib/i18n/index.js';
	import { showErr } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';
	let zones = $state([]);
	api.get('/user/domains').then((d) => (zones = d.filter((x) => x.kind !== 'sub'))).catch(showErr);
</script>

<PageHead title={$t('tools.zone_editor')} desc={$t('dns.list_desc')} icon={Network} />
<div class="card">
	<div class="tw"><table class="table">
		<thead><tr><th>{$t('domains.domain')}</th><th>{$t('domains.type')}</th><th><span class="sr-only">{$t('common.actions')}</span></th></tr></thead>
		<tbody>
			{#each zones as z}
				<tr><td><a href={'/dns/' + z.name}>{z.name}</a></td><td><span class="badge">{$t('domains.kind_' + z.kind)}</span></td>
					<td><div class="actions">
						{#each ['A', 'CNAME', 'MX'] as ty}<a class="btn sm ghost" href={'/dns/' + z.name + '?add=' + ty}>+{ty}<span class="sr-only"> — {$t('dns.quick_add', { type: ty, zone: z.name })}</span></a>{/each}
						<a class="btn sm" href={'/dns/' + z.name}>{$t('common.manage')}<span class="sr-only"> — {$t('domains.dns_named', { name: z.name })}</span> <ChevronRight size={14} /></a></div></td></tr>
			{:else}<tr><td colspan="3" class="empty">{$t('common.loading')}</td></tr>{/each}
		</tbody>
	</table></div>
</div>
