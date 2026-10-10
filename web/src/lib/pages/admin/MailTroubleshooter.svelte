<script>
	// v1.1: Mail Troubleshooter — how would this server route an address (Postfix maps + DNS).
	import { Stethoscope } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t } from '$lib/i18n/index.js';
	import { showErr } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';
	let address = $state('');
	let res = $state(null);
	let busy = $state(false);
	async function run(e) {
		e.preventDefault(); busy = true;
		try { res = await api.get('/admin/mail-troubleshooter?address=' + encodeURIComponent(address)); } catch (err) { showErr(err); }
		busy = false;
	}
	const label = (c) => { const k = 'v11.chk_' + c; const s = $t(k); return s === k ? c : s; };
</script>

<PageHead title={$t('tools.mail_troubleshooter')} desc={$t('v11.mt_desc')} icon={Stethoscope} />
<form class="card" onsubmit={run}><div class="card-body row wraprow">
	<label class="field" style="max-width:420px"><span>{$t('v11.address')}</span><input bind:value={address} required placeholder="user@example.com" maxlength="254" /></label>
	<button class="btn primary" disabled={busy}>{$t('v11.trace')}</button>
</div></form>
{#if res}
	{#if res.status === 'not_installed'}<div class="card pad">{$t('v11.not_installed')} <span class="muted small">{res.reason}</span></div>{/if}
	<div class="card tw"><table class="table small"><tbody>
		{#each res.steps as s}<tr><td>{label(s.check)}</td><td><span class="badge" class:green={s.result === 'pass'} class:red={s.result === 'fail'} class:amber={s.result === 'info'}>{$t('v11.res_' + s.result)}</span></td><td class="mono">{s.detail ?? ''}</td></tr>{/each}
	</tbody></table></div>
{/if}

<style>.wraprow { flex-wrap: wrap; align-items: flex-end; gap: 12px; }</style>
