<script>
	import { Webhook } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t, fmt } from '$lib/i18n/index.js';
	import { showErr, ok } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';
	let hooks = $state([]);
	let allowPrivate = $state(false);
	let store = $state(null);
	let form = $state({ name: '', url: '', events: '' });
	let shown = $state('');
	let log = $state(null);
	let logFor = $state(0);
	async function load() {
		try { const r = await api.get('/admin/webhooks'); hooks = r.webhooks; allowPrivate = r.allow_private; store = r.secret_store; } catch (e) { showErr(e); }
	}
	load();
	const evList = (s) => s.split(',').map((x) => x.trim()).filter(Boolean);
	async function create(e) {
		e.preventDefault();
		try {
			const r = await api.post('/admin/webhooks', { name: form.name, url: form.url, events: evList(form.events) });
			shown = r.secret; form = { name: '', url: '', events: '' }; ok('sec.wh_created'); load();
		} catch (err) { showErr(err); }
	}
	async function toggle(h) { try { await api.put('/admin/webhooks/' + h.id, { enabled: !h.enabled }); load(); } catch (e) { showErr(e); } }
	async function del(h) { if (!confirm($t('sec.wh_confirm_delete', { name: h.name }))) return; try { await api.del('/admin/webhooks/' + h.id); load(); } catch (e) { showErr(e); } }
	async function rotate(h) { try { shown = (await api.post('/admin/webhooks/' + h.id + '/secret')).secret; } catch (e) { showErr(e); } }
	async function test(h) { try { await api.post('/admin/webhooks/' + h.id + '/test'); ok('sec.wh_test_queued'); } catch (e) { showErr(e); } }
	async function showLog(h) { try { logFor = h.id; log = (await api.get('/admin/webhooks/' + h.id + '/deliveries')).deliveries; } catch (e) { showErr(e); } }
	async function setPrivate() { try { await api.put('/admin/webhooks/settings', { allow_private: !allowPrivate }); load(); } catch (e) { showErr(e); } }
</script>

<PageHead title={$t('tools.webhooks')} desc={$t('sec.wh_desc')} icon={Webhook} />
{#if store && store.status !== 'ok'}<div class="card"><span class="badge red">{$t('sec.secret_store')}: {store.status}</span> <span class="muted small">{store.reason}</span></div>{/if}
{#if shown}
	<div class="card"><p>{$t('sec.wh_secret_once')}</p><code class="mono">{shown}</code> <button class="btn" onclick={() => (shown = '')}>{$t('common.close')}</button></div>
{/if}
<form class="card" onsubmit={create}>
	<h3>{$t('sec.wh_new')}</h3>
	<label>{$t('sec.wh_name')} <input bind:value={form.name} required maxlength="64" /></label>
	<label>{$t('sec.wh_url')} <input type="url" bind:value={form.url} required placeholder="https://example.com/hook" /></label>
	<label>{$t('sec.wh_events')} <input bind:value={form.events} placeholder="shield.*, netsec.ban" /></label>
	<p class="muted small">{$t('sec.wh_events_hint')}</p>
	<button class="btn primary" type="submit">{$t('sec.wh_create')}</button>
</form>
<div class="card">
	<div class="tw"><table class="table">
		<thead><tr><th>{$t('sec.wh_name')}</th><th>{$t('sec.wh_url')}</th><th>{$t('sec.wh_events')}</th><th>{$t('sec.wh_enabled')}</th><th></th></tr></thead>
		<tbody>
			{#each hooks as h}
				<tr><td>{h.name}</td><td class="mono small">{h.url}</td><td class="small">{h.events.length ? h.events.join(', ') : $t('sec.wh_all_events')}</td>
					<td><button class="btn small" onclick={() => toggle(h)}>{h.enabled ? $t('sec.on') : $t('sec.off')}</button></td>
					<td class="nowrap"><button class="btn small" onclick={() => test(h)}>{$t('sec.wh_test')}</button> <button class="btn small" onclick={() => showLog(h)}>{$t('sec.wh_log')}</button> <button class="btn small" onclick={() => rotate(h)}>{$t('sec.wh_rotate')}</button> <button class="btn small danger" onclick={() => del(h)}>{$t('common.delete')}</button></td></tr>
			{:else}<tr><td colspan="5" class="empty">{$t('common.none')}</td></tr>{/each}
		</tbody>
	</table></div>
	<label class="small"><input type="checkbox" checked={allowPrivate} onchange={setPrivate} /> {$t('sec.wh_allow_private')}</label>
	<p class="muted small">{$t('sec.wh_allow_private_hint')}</p>
</div>
{#if log}
	<div class="card">
		<h3>{$t('sec.wh_log')} #{logFor}</h3>
		<div class="tw"><table class="table">
			<thead><tr><th>{$t('sec.time')}</th><th>{$t('sec.status')}</th><th>{$t('sec.attempts')}</th><th>HTTP</th><th>{$t('sec.error')}</th></tr></thead>
			<tbody>
				{#each log as d}<tr><td class="small">{$fmt.date(d.created_at)}</td><td><span class="badge" class:green={d.status === 'delivered'} class:red={d.status === 'failed'}>{$t('sec.st_' + d.status)}</span></td><td>{d.attempts}</td><td>{d.http_status || '—'}</td><td class="small mono">{d.error}</td></tr>
				{:else}<tr><td colspan="5" class="empty">{$t('common.none')}</td></tr>{/each}
			</tbody>
		</table></div>
	</div>
{/if}
