<script>
	// R2-UX-01: shown to resellers who open an administrator-only tool by URL.
	import { ShieldAlert } from '@lucide/svelte';
	import { t } from '$lib/i18n/index.js';
	import PageHead from '$lib/components/PageHead.svelte';
</script>

<PageHead title={$t('errors.admin_only_title')} icon={ShieldAlert} back="/" backLabel={$t('nav.home')} />
<div class="card card-body">
	<div class="alert warn" role="status"><ShieldAlert size={18} aria-hidden="true" /><div>{$t('errors.admin_only')}</div></div>
	<a class="btn" href="/">{$t('nav.home')}</a>
</div>
