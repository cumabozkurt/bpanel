<script>
	import { UserCog, Languages, Palette } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { session, meta, applyTheme, loadSession } from '$lib/stores.js';
	import { t, languages, locale, setLocale } from '$lib/i18n/index.js';
	import { showErr, ok } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';

	let lang = $state($session?.user?.lang || '');
	let theme = $state($session?.user?.theme || 'light');

	async function save(e) {
		e.preventDefault();
		try {
			await api.put('/account/preferences', { lang, theme });
			setLocale(lang || $session?.default_lang || $meta?.default_lang || 'en', !!lang);
			if (!lang) localStorage.removeItem('bp_lang');
			applyTheme(theme);
			await loadSession();
			ok('prefs.saved');
		} catch (err) { showErr(err); }
	}
</script>

<PageHead title={$t('prefs.title')} desc={$t('prefs.desc')} icon={UserCog} />
<form class="card" onsubmit={save} style="max-width:640px">
	<div class="card-body">
		<label class="field"><span><Languages size={14} /> {$t('prefs.language')}</span>
			<select bind:value={lang}>
				<option value="">{$t('prefs.server_default', { lang: languages.find((l) => l.code === ($session?.default_lang || 'en'))?.name ?? 'English' })}</option>
				{#each languages as l}<option value={l.code}>{l.name}</option>{/each}
			</select>
			<small>{$t('prefs.language_help')}</small>
		</label>
		<fieldset class="field">
			<legend><Palette size={14} /> {$t('prefs.theme')}</legend>
			{#each ['light', 'dark', 'system'] as th}
				<label class="radio"><input type="radio" bind:group={theme} value={th} /> {$t('prefs.theme_' + th)}</label>
			{/each}
		</fieldset>
		<div class="kv small" style="margin-bottom:16px">
			<div>{$t('prefs.contact_email')}</div><div>{$session?.user?.email || '—'}</div>
		</div>
		<button class="btn primary">{$t('common.save')}</button>
	</div>
</form>

<style>
	fieldset { border: 0; padding: 0; margin: 0 0 16px; }
	legend { font-weight: 600; font-size: 13px; margin-bottom: 6px; }
	.radio { display: inline-flex; gap: 6px; align-items: center; margin-right: 18px; }
</style>
