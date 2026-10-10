<script>
	// v1.1: Site Publisher — publish a ready-made one-page site (index.html) into a domain's document root.
	import { LayoutTemplate, Send } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t, locale } from '$lib/i18n/index.js';
	import { showErr, ok, ask } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';
	let info = $state(null);
	let f = $state({ domain_id: null, template: 'business', lang: 'en', overwrite: false, fields: { title: '', tagline: '', about: '', email: '', phone: '', address: '', accent: '#2563eb' } });
	let done = $state(null);
	async function load() {
		try {
			info = await api.get('/user/site-publisher');
			f.domain_id = info.domains[0]?.id ?? null;
			f.lang = $locale === 'tr' ? 'tr' : 'en';
		} catch (e) { showErr(e); }
	}
	async function publish(e) {
		e.preventDefault();
		try { done = await api.post('/user/site-publisher', f); ok('v11.site_published'); } catch (err) {
			if (err?.code === 'site_exists' && ask('v11.site_overwrite_confirm')) { f.overwrite = true; return publish(e); }
			showErr(err);
		}
	}
	load();
</script>

<PageHead title={$t('tools.site_publisher')} desc={$t('v11.site_desc')} icon={LayoutTemplate} />
{#if info}
	<form class="card" onsubmit={publish}><div class="card-body stack">
		<div class="row wraprow">
			<label class="field"><span>{$t('webx.domain')}</span><select bind:value={f.domain_id} required>{#each info.domains as d}<option value={d.id}>{d.name}</option>{/each}</select></label>
			<label class="field"><span>{$t('v11.template')}</span><select bind:value={f.template}>{#each info.templates as tp}<option value={tp.id}>{$t('v11.tpl_' + tp.id)}</option>{/each}</select></label>
			<label class="field"><span>{$t('v11.site_lang')}</span><select bind:value={f.lang}><option value="en">English</option><option value="tr">Türkçe</option></select></label>
			<label class="field"><span>{$t('v11.accent')}</span><input type="color" bind:value={f.fields.accent} /></label>
		</div>
		<label class="field"><span>{$t('v11.site_title')}</span><input bind:value={f.fields.title} required maxlength="120" /></label>
		<label class="field"><span>{$t('v11.tagline')}</span><input bind:value={f.fields.tagline} maxlength="200" /></label>
		<label class="field"><span>{$t('v11.about')}</span><textarea rows="4" bind:value={f.fields.about} maxlength="2000"></textarea></label>
		<div class="row wraprow">
			<label class="field"><span>{$t('newacc.email')}</span><input type="email" bind:value={f.fields.email} maxlength="254" /></label>
			<label class="field"><span>{$t('v11.phone')}</span><input bind:value={f.fields.phone} maxlength="40" /></label>
			<label class="field"><span>{$t('v11.address')}</span><input bind:value={f.fields.address} maxlength="200" /></label>
		</div>
		<label class="check"><input type="checkbox" bind:checked={f.overwrite} /> {$t('v11.overwrite')}</label>
		<div><button class="btn primary" disabled={!f.domain_id}><Send size={14} /> {$t('v11.publish')}</button></div>
		{#if done}<p class="small">{$t('v11.site_written', { path: done.path })} <a href={done.url} target="_blank" rel="noopener">{done.url}</a></p>{/if}
	</div></form>
{/if}

<style>.wraprow { flex-wrap: wrap; align-items: flex-end; gap: 12px; } .check { display: flex; gap: 8px; align-items: center; }</style>
