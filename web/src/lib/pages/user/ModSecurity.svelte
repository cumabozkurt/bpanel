<script>
	import { ShieldAlert, Lock } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t } from '$lib/i18n/index.js';
	import { showErr, ok } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';

	// v0.4 usagex: WAF (ModSecurity + OWASP CRS, free) mode of own domains.
	let data = $state(null);
	let busy = $state('');
	async function load() {
		try { data = await api.get('/user/waf'); } catch (e) { showErr(e); }
	}
	async function setMode(d, mode) {
		busy = d.domain;
		try {
			const r = await api.put(`/user/waf/${encodeURIComponent(d.domain)}`, { mode });
			ok(r.status === 'applied' ? 'usagex.waf_applied' : 'usagex.waf_saved');
			load();
		} catch (e) { showErr(e); load(); }
		busy = '';
	}
	load();
</script>

<PageHead title={$t('usagex.waf_title')} desc={$t('usagex.waf_desc')} icon={ShieldAlert} />
{#if data}
	{#if data.provider.status !== 'installed' && data.provider.status !== 'ok'}
		<div class="card pad warn" role="status">{$t('usagex.waf_provider', { status: data.provider.status, reason: data.provider.reason || '' })}</div>
	{/if}
	<div class="card tw">
		<table class="table">
			<thead><tr><th>{$t('acc.domain')}</th><th>{$t('usagex.waf_mode')}</th><th>{$t('usagex.tok_status')}</th></tr></thead>
			<tbody>
				{#each data.domains as d (d.domain)}
					<tr><td>{d.domain} {#if d.locked}<span title={$t('usagex.waf_locked_hint')}><Lock size={13} /></span>{/if}</td>
						<td><select value={d.mode} disabled={d.locked || busy === d.domain} aria-label={$t('usagex.waf_mode')} onchange={(e) => setMode(d, e.currentTarget.value)}>
							{#each ['block', 'audit', 'off'] as m}<option value={m}>{$t('usagex.waf_m.' + m)}</option>{/each}</select></td>
						<td>{d.status || '—'}{d.reason ? ' — ' + d.reason : ''}</td></tr>
				{:else}<tr><td colspan="3" class="empty">{$t('usagex.waf_empty')}</td></tr>{/each}
			</tbody>
		</table>
	</div>
	<p class="small muted">{$t('usagex.waf_help')}</p>
{/if}
