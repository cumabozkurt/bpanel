<script>
	// v1.1: Email Routing — local, backup MX, remote or automatic (by the domain's MX records).
	import { Route } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t } from '$lib/i18n/index.js';
	import { showErr, ok } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';
	let data = $state(null);
	async function load() { try { data = await api.get('/user/email/routing'); } catch (e) { showErr(e); } }
	async function set(d, mode) {
		try {
			const r = await api.put('/user/email/routing/' + encodeURIComponent(d.domain), { mode });
			ok(r.status === 'not_installed' ? 'v11.routing_saved_pending' : 'v11.routing_saved', { domain: d.domain, mode: $t('v11.routing_' + r.effective) });
			load();
		} catch (e) { showErr(e); }
	}
	load();
</script>

<PageHead title={$t('tools.email_routing')} desc={$t('v11.routing_desc')} icon={Route} />
{#if data}
	<div class="card tw">
		<table class="table">
			<thead><tr><th>{$t('acc.domain')}</th><th>{$t('v11.routing_mode')}</th><th>{$t('v11.routing_effective')}</th><th>MX</th></tr></thead>
			<tbody>
				{#each data.domains as d (d.domain)}
					<tr>
						<td>{d.domain}</td>
						<td><select value={d.mode} onchange={(e) => set(d, e.currentTarget.value)} aria-label={$t('v11.routing_mode')}>
							{#each data.modes as m}<option value={m}>{$t('v11.routing_' + m)}</option>{/each}</select></td>
						<td><span class="badge" class:green={d.effective === 'local'} class:amber={d.effective !== 'local'}>{$t('v11.routing_' + d.effective)}</span></td>
						<td class="mono small">{d.mx.join(', ') || '—'} {#if d.mx.length}<span class="muted">({d.mx_local ? $t('v11.mx_local') : $t('v11.mx_remote')})</span>{/if}</td>
					</tr>
				{:else}<tr><td colspan="4" class="empty">{$t('v11.no_mail_domains')}</td></tr>{/each}
			</tbody>
		</table>
	</div>
	<p class="muted small">{$t('v11.routing_help')}</p>
{/if}
