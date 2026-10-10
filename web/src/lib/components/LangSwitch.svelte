<script>
	import { Languages } from '@lucide/svelte';
	import { languages, locale, setLocale, t } from '$lib/i18n/index.js';
	import { api } from '$lib/api.js';
	import { session } from '$lib/stores.js';
	let { compact = false } = $props();
	async function change(e) {
		const code = e.currentTarget.value;
		setLocale(code);
		if ($session) {
			try { await api.put('/account/preferences', { lang: code }); } catch {}
		}
	}
</script>

<label class="ls" class:compact title={$t('prefs.language')}>
	<Languages size={16} />
	<span class="sr-only">{$t('prefs.language')}</span>
	<select value={$locale} onchange={change}>
		{#each languages as l}<option value={l.code}>{l.name}</option>{/each}
	</select>
</label>

<style>
	.ls { display: inline-flex; align-items: center; gap: 6px; color: var(--text-2); }
	select { width: auto; min-height: 30px; padding: 3px 6px; background: transparent; }
	.compact select { border-color: transparent; }
</style>
