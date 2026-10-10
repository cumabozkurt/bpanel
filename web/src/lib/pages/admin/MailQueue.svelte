<script>
	// v1.1: Mail Queue Manager — Postfix queue: search, view, delete, hold, release, requeue, deliver, flush.
	import { Inbox, Eye } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t } from '$lib/i18n/index.js';
	import { showErr, ok, ask } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';
	let data = $state(null);
	let q = $state('');
	let sel = $state({});
	let view = $state(null);
	let busy = $state(false);
	const ids = () => Object.keys(sel).filter((k) => sel[k]);
	async function load() { try { data = await api.get('/admin/mail-queue' + (q ? '?q=' + encodeURIComponent(q) : '')); sel = {}; } catch (e) { showErr(e); } }
	async function act(action, all = false) {
		const list = ids();
		if (action === 'delete' && !ask(all ? 'v11.mq_delete_all_confirm' : 'v11.mq_delete_confirm', { n: list.length })) return;
		busy = true;
		try { const r = await api.post('/admin/mail-queue/action', { action, ids: all ? [] : list, all }); ok('v11.mq_done', { n: r.affected ?? 0 }); load(); } catch (e) { showErr(e); }
		busy = false;
	}
	async function show(m) { try { view = { id: m.id, ...(await api.get('/admin/mail-queue/' + encodeURIComponent(m.id))) }; } catch (e) { showErr(e); } }
	const when = (u) => (u ? new Date(u * 1000).toLocaleString() : '—');
	load();
</script>

<PageHead title={$t('tools.mail_queue')} desc={$t('v11.mq_desc')} icon={Inbox} />
<div class="stack">
	<div class="card"><div class="card-body row wraprow">
		<label class="field" style="max-width:320px"><span>{$t('v11.search')}</span><input bind:value={q} placeholder="user@example.com" onkeydown={(e) => e.key === 'Enter' && load()} /></label>
		<button class="btn" onclick={load}>{$t('v11.refresh')}</button>
		{#each ['deliver', 'hold', 'release', 'requeue', 'delete'] as a}<button class="btn" class:danger={a === 'delete'} disabled={busy || !ids().length} onclick={() => act(a)}>{$t('v11.mq_' + a)}</button>{/each}
		<button class="btn" disabled={busy} onclick={() => act('flush')}>{$t('v11.mq_flush')}</button>
		<button class="btn danger" disabled={busy || !data?.messages?.length} onclick={() => act('delete', true)}>{$t('v11.mq_delete_all')}</button>
	</div></div>
	{#if data}
		{#if data.status === 'not_installed'}<div class="card pad">{$t('v11.not_installed')} <span class="muted small">{data.reason}</span></div>{/if}
		<div class="card tw"><table class="table small">
			<thead><tr><th></th><th>ID</th><th>{$t('v11.queue')}</th><th>{$t('v11.sender')}</th><th>{$t('v11.recipients')}</th><th>{$t('v11.size')}</th><th>{$t('v11.arrival')}</th><th></th></tr></thead>
			<tbody>
				{#each data.messages as m (m.id)}
					<tr><td><input type="checkbox" bind:checked={sel[m.id]} aria-label={m.id} /></td><td class="mono">{m.id}</td><td><span class="badge" class:amber={m.queue === 'deferred'}>{m.queue}</span></td><td class="mono">{m.sender || '<>'}</td>
						<td class="mono">{#each m.recipients as r}<div>{r.address}{#if r.reason} <span class="muted">— {r.reason}</span>{/if}</div>{/each}</td><td>{m.size}</td><td>{when(m.arrival)}</td>
						<td><button class="btn ghost sm" aria-label={$t('v11.view')} onclick={() => show(m)}><Eye size={14} /></button></td></tr>
				{:else}<tr><td colspan="8" class="empty">{$t('v11.mq_empty')}</td></tr>{/each}
			</tbody></table></div>
		<p class="muted small">{$t('v11.mq_total', { n: data.total ?? 0 })}</p>
	{/if}
	{#if view}<div class="card pad"><p class="mono small">{view.id} {view.truncated ? '· ' + $t('v11.truncated') : ''}</p><pre class="mono small pre">{view.text}</pre><button class="btn sm" onclick={() => (view = null)}>{$t('v11.close')}</button></div>{/if}
</div>

<style>.wraprow { flex-wrap: wrap; align-items: flex-end; gap: 8px; } .pre { max-height: 420px; overflow: auto; white-space: pre-wrap; }</style>
