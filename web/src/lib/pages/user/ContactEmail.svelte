<script>
	// v0.4 adminx: change own contact email (audited; no outbound mail path).
	import { Contact } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t } from '$lib/i18n/index.js';
	import { showErr, ok } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';
	let email = $state('');
	api.get('/user/contact-email').then((r) => (email = r.email)).catch(showErr);
	async function save(e) { e.preventDefault(); try { email = (await api.put('/user/contact-email', { email })).email; ok('adminx.saved'); } catch (err) { showErr(err); } }
</script>

<PageHead title={$t('tools.contact_info')} desc={$t('adminx.contact_own_desc')} icon={Contact} />
<form class="card" onsubmit={save}>
	<label>{$t('adminx.contact_email')} <input type="email" bind:value={email} required maxlength="254" /></label>
	<p class="muted small">{$t('adminx.contact_no_notify')}</p>
	<button class="btn primary" type="submit">{$t('adminx.save')}</button>
</form>
