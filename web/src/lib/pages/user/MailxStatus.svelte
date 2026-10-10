<script>
	import { t } from '$lib/i18n/index.js';
	let { status = '', reason = '' } = $props();
	const cls = { active: 'green', ok: 'green', inactive: '', not_installed: 'amber' };
</script>

{#if status}<span class="badge {cls[status] ?? ''}" title={reason}>{$t('mailx.status_' + status)}</span>{/if}
