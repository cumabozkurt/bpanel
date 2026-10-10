<script>
	import { FileWarning, FileText, RefreshCw } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t } from '$lib/i18n/index.js';
	import { showErr } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';
	let { params } = $props();
	let domains = $state([]);
	let domain = $state('');
	let lines = $state(null);
	let kind = $derived(params.kind === 'error' ? 'error' : 'access');
	async function load() {
		lines = null;
		try { lines = (await api.get(`/user/logs?kind=${kind}&domain=${encodeURIComponent(domain)}`)).lines ?? []; } catch (e) { showErr(e); lines = []; }
	}
	api.get('/user/domains').then((d) => { domains = d.filter((x) => x.kind !== 'alias').map((x) => x.name); domain = domains[0] ?? ''; load(); }).catch(showErr);
</script>

<PageHead title={kind === 'error' ? $t('tools.errors') : $t('tools.raw_access')} desc={kind === 'error' ? $t('logs.error_desc') : $t('logs.access_desc')} icon={kind === 'error' ? FileWarning : FileText} />
<div class="card">
	<div class="toolbar">
		<select bind:value={domain} onchange={load} style="width:auto" aria-label={$t('domains.domain')}>{#each domains as d}<option>{d}</option>{/each}</select>
		<button class="btn sm" onclick={load}><RefreshCw size={14} /> {$t('fm.reload')}</button>
		<span class="grow"></span><span class="muted small">{$t('logs.newest_first')}</span>
	</div>
	<!-- svelte-ignore a11y_no_noninteractive_tabindex -->
	<pre class="log" tabindex="0" role="log" aria-label={(kind === 'error' ? $t('tools.errors') : $t('tools.raw_access')) + (domain ? ' — ' + domain : '')} aria-busy={lines === null}>{#if lines === null}{$t('common.loading')}{:else if lines.length === 0}{$t('logs.empty')}{:else}{lines.join('\n')}{/if}</pre>
</div>

<style>.log:focus-visible { outline: 2px solid var(--primary); outline-offset: -2px; } .log { margin: 0; padding: 14px; font-family: var(--mono); font-size: 12px; line-height: 1.6; max-height: 68vh; overflow: auto; white-space: pre-wrap; word-break: break-all; background: var(--card-2); }</style>
