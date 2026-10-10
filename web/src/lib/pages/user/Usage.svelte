<script>
	import { Gauge } from '@lucide/svelte';
	import { t } from '$lib/i18n/index.js';
	import PageHead from '$lib/components/PageHead.svelte';
	import UsagePanel from '$lib/components/UsagePanel.svelte';
</script>

<PageHead title={$t('iso.user_title')} desc={$t('iso.user_desc')} icon={Gauge} />
<div class="card pad"><UsagePanel src="/user/usage" /></div>
