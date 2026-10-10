<script>
	import { Settings2 } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t } from '$lib/i18n/index.js';
	import { showErr, ok } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';

	// v0.4 usagex: allowlisted PHP settings of the own FPM pool, per version.
	let data = $state(null);
	let form = $state({});
	let version = $state('');
	let busy = $state(false);
	const sizeKeys = ['memory_limit', 'upload_max_filesize', 'post_max_size'];

	async function load(v) {
		try {
			data = await api.get('/user/php-ini' + (v ? '?version=' + encodeURIComponent(v) : ''));
			version = data.version;
			form = Object.fromEntries(data.keys.map((k) => [k, data.settings[k] ?? '']));
		} catch (e) { showErr(e); }
	}
	async function save(e) {
		e.preventDefault();
		busy = true;
		try {
			await api.put('/user/php-ini', { version, settings: form });
			ok('usagex.php_saved');
			load(version);
		} catch (err) { showErr(err); }
		busy = false;
	}
	load();
</script>

<PageHead title={$t('usagex.php_title')} desc={$t('usagex.php_desc')} icon={Settings2} />
{#if data}
	<form class="card pad" onsubmit={save}>
		<label class="field"><span>{$t('usagex.php_version')}</span>
			<select bind:value={version} onchange={() => load(version)}>{#each data.versions as v}<option value={v}>PHP {v}</option>{/each}</select></label>
		{#each data.keys as k}
			<label class="field"><span><code>{k}</code></span>
				{#if k === 'display_errors'}
					<select bind:value={form[k]}><option value="">{$t('usagex.php_default', { v: data.effective[k] })}</option><option value="On">On</option><option value="Off">Off</option></select>
				{:else}
					<input bind:value={form[k]} maxlength="64" placeholder={data.effective[k]} spellcheck="false" />
				{/if}
				{#if k === 'memory_limit'}<small class="muted">{$t('usagex.php_mem_cap', { mb: data.memory_cap_mb })}</small>{/if}
				{#if sizeKeys.includes(k) && k !== 'memory_limit'}<small class="muted">{$t('usagex.php_size_help')}</small>{/if}
				{#if k === 'date.timezone'}<small class="muted">{$t('usagex.php_tz_help')}</small>{/if}
			</label>
		{/each}
		<p class="small muted">{$t('usagex.php_help')}</p>
		<button class="btn primary" disabled={busy}>{$t('common.save')}</button>
	</form>
{/if}
