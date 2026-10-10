<script>
	// v1.1: Billing integration (WHMCS) — provisioning endpoints and lifecycle events for webhooks.
	import { Receipt } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t } from '$lib/i18n/index.js';
	import { showErr } from '$lib/util.js';
	import { nav } from '$lib/router.js';
	import PageHead from '$lib/components/PageHead.svelte';
	let data = $state(null);
	api.get('/admin/billing').then((r) => (data = r)).catch(showErr);
</script>

<PageHead title={$t('tools.billing')} desc={$t('v11.billing_desc')} icon={Receipt} />
{#if data}
	<div class="stack">
		<div class="card tw"><div class="card-head"><h2>{$t('v11.provisioning')}</h2></div>
			<table class="table small"><thead><tr><th>WHMCS</th><th>{$t('v11.method')}</th><th>API</th></tr></thead>
				<tbody>{#each data.provisioning as p}<tr><td>{p.action}</td><td>{p.method}</td><td class="mono">{p.path}</td></tr>{/each}</tbody></table></div>
		<div class="card pad"><h3>{$t('v11.events')}</h3><p class="mono small">{data.events.join(' · ')}</p>
			<p class="small">{$t('v11.billing_help')}</p>
			<p class="small"><button class="linkbtn" onclick={() => nav('/webhooks')}>{$t('tools.webhooks')}</button> · <span class="mono">{data.docs}</span> · <span class="mono">{data.example}</span></p></div>
	</div>
{/if}
