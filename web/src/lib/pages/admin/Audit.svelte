<script>
	import { ScrollText } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t, fmt } from '$lib/i18n/index.js';
	import { showErr } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';
	import SortTh from '$lib/components/SortTh.svelte';
	import Pager from '$lib/components/Pager.svelte';
	import { TableState } from '$lib/table.svelte.js';
	import { auditLabel } from '$lib/util.js';
	const tbl = new TableState(() => rows, { key: 'at', dir: -1, size: 50 });
	let rows = $state([]);
	let q = $state('');
	let timer;
	async function load() { try { rows = await api.get('/admin/audit?limit=1000&q=' + encodeURIComponent(q)); tbl.reset(); } catch (e) { showErr(e); } }
	load();
	function onInput() { clearTimeout(timer); timer = setTimeout(load, 250); }
</script>

<PageHead title={$t('tools.audit_log')} desc={$t('audit.desc')} icon={ScrollText} />
<div class="card">
	<div class="toolbar"><input type="search" bind:value={q} oninput={onInput} placeholder={$t('common.search')} aria-label={$t('common.search')} /></div>
	<div class="tw">
	<table class="table">
		<thead><tr><SortTh {tbl} key="at" label={$t('audit.time')} /><SortTh {tbl} key="actor" label={$t('audit.actor')} /><SortTh {tbl} key="ip" label={$t('audit.ip')} /><SortTh {tbl} key="realm" label={$t('audit.panel')} /><SortTh {tbl} key="action" label={$t('audit.action')} /><th>{$t('audit.target')}</th><SortTh {tbl} key="ok" label={$t('audit.result')} /></tr></thead>
		<tbody>
			{#each tbl.page as r}
				<tr><td class="small">{$fmt.date(r.at)}</td><td>{r.actor || '—'}</td><td class="mono small">{r.ip}</td><td><span class="badge">{$t('audit.realm_' + r.realm) === 'audit.realm_' + r.realm ? (r.realm || '—') : $t('audit.realm_' + r.realm)}</span></td>
					<td class="small" title={r.action}>{auditLabel(r.action)}</td><td class="small">{r.target} <span class="muted">{r.detail}</span></td>
					<td>{#if r.ok}<span class="badge green">{$t('audit.ok')}</span>{:else}<span class="badge red">{$t('audit.failed')}</span>{/if}</td></tr>
			{:else}<tr><td colspan="7" class="empty">{$t('common.none')}</td></tr>{/each}
		</tbody>
	</table>
	</div>
	<Pager {tbl} sizes={[50, 100, 250]} />
</div>
