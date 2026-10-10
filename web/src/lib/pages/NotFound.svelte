<script>
	import { t } from '$lib/i18n/index.js';
	import { pageTitle } from '$lib/stores.js';
	$effect(() => { pageTitle.set($t('common.not_found_title')); return () => pageTitle.set(''); });
</script>

<div class="card empty">
	<h1>404</h1>
	<p>{$t('common.not_found')}</p>
	<a class="btn" href="/">{$t('nav.home')}</a>
</div>
