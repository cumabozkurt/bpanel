<script>
	import { Plug, RefreshCw } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t, fmt } from '$lib/i18n/index.js';
	import { showErr } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';
	let data = $state(null);
	let busy = $state(false);
	async function load(refresh = false) {
		busy = true;
		try { data = await api.get('/admin/integrations' + (refresh ? '?refresh=1' : '')); } catch (e) { showErr(e); }
		busy = false;
	}
	load();
	const stateClass = { installed: 'green', not_installed: '', not_configured: 'amber', unsupported_env: 'amber', health_failed: 'red' };
	// unknown codes fall back to the raw code instead of a missing-key marker
	function tr(prefix, code) { const k = prefix + code; const v = $t(k); return v === k ? code : v; }
</script>

<PageHead title={$t('prov.title')} desc={$t('prov.desc')} icon={Plug}>
	{#snippet actions()}<button class="btn" disabled={busy} onclick={() => load(true)}><RefreshCw size={15} class={busy ? 'spin' : ''} /> {$t('prov.refresh')}</button>{/snippet}
</PageHead>
{#if data}<p class="small muted">{$t('prov.checked', { time: $fmt.date(Date.parse(data.checked_at) / 1000) })}{data.cached ? ' · ' + $t('prov.cached') : ''}</p>{/if}
<div class="card tw">
	<table class="table">
		<thead><tr><th>{$t('prov.name')}</th><th>{$t('prov.kind')}</th><th>{$t('prov.license')}</th><th>{$t('prov.status')}</th><th>{$t('prov.version')}</th><th>{$t('prov.reason_col')}</th></tr></thead>
		<tbody>
			{#each data?.providers ?? [] as p (p.name)}
				<tr>
					<td><b>{p.title}</b><div class="mono small muted">{p.name}</div></td>
					<td>{tr('prov.kinds.', p.kind)}</td>
					<td>
						<span class="badge {p.license.class === 'commercial_optional' ? 'amber' : 'green'}">{tr('prov.lic.', p.license.class)}</span>
						<div class="small muted">{p.license.spdx}{p.license.bundled ? ' · ' + $t('prov.lic.bundled') : ''}</div>
					</td>
					<td><span class="badge {stateClass[p.state] ?? ''}"><span aria-hidden="true">●</span> {tr('prov.state.', p.state)}</span></td>
					<td class="mono small">{p.version || '—'}</td>
					<td class="small">{p.reason ? tr('prov.reason.', p.reason) : '—'}{#if p.detail}<div class="mono small muted">{p.detail}</div>{/if}</td>
				</tr>
			{:else}<tr><td colspan="6" class="empty">{busy ? $t('common.loading') : '—'}</td></tr>{/each}
		</tbody>
	</table>
</div>
<p class="small muted">{$t('prov.commercial_note')}</p>
