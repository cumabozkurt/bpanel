<script>
	import { PlugZap } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t } from '$lib/i18n/index.js';
	import { showErr, ok } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';

	let res = $state(null);
	let archive = $state('');
	let review = $state(null);
	let busy = $state(false);
	let key = $state({ name: '', pubkey: '' });
	let open = $state('');

	async function load() {
		try { res = await api.get('/admin/plugins'); } catch (e) { showErr(e); }
	}
	function pick(e) {
		review = null; archive = '';
		const f = e.currentTarget.files?.[0];
		if (!f) return;
		if (res && f.size > res.max_archive_bytes) { showErr({ code: 'plugin_too_large' }); return; }
		const r = new FileReader();
		r.onload = async () => {
			archive = String(r.result).split(',')[1] ?? '';
			busy = true;
			try { review = await api.post('/admin/plugins/inspect', { archive }); } catch (err) { showErr(err); archive = ''; }
			busy = false;
		};
		r.readAsDataURL(f);
	}
	async function install() {
		busy = true;
		try { await api.post('/admin/plugins', { archive }); ok('clusterx.installed'); review = null; archive = ''; load(); } catch (err) { showErr(err); }
		busy = false;
	}
	async function toggle(p) {
		try { await api.post('/admin/plugins/' + p.name + '/enable', { enabled: !p.enabled }); load(); } catch (err) { showErr(err); }
	}
	async function remove(p) {
		if (!confirm($t('clusterx.confirm_remove', { ip: p.name }))) return;
		try { await api.del('/admin/plugins/' + p.name); load(); } catch (err) { showErr(err); }
	}
	async function addKey(e) {
		e.preventDefault();
		try { await api.post('/admin/plugin-keys', key); key = { name: '', pubkey: '' }; ok('common.saved'); load(); } catch (err) { showErr(err); }
	}
	async function delKey(k) {
		if (!confirm($t('clusterx.confirm_remove', { ip: k.name }))) return;
		try { await api.del('/admin/plugin-keys/' + k.id); load(); } catch (err) { showErr(err); }
	}
	load();
</script>

<PageHead title={$t('tools.plugins')} desc={$t('clusterx.plugins_desc')} icon={PlugZap} />

{#if res}
<section class="card">
	<h3>{$t('clusterx.installed_plugins')}</h3>
	<table class="table">
		<thead><tr><th>{$t('clusterx.plugin')}</th><th>{$t('clusterx.version')}</th><th>{$t('clusterx.author')}</th><th>{$t('clusterx.perms')}</th><th>{$t('clusterx.signer')}</th><th></th></tr></thead>
		<tbody>
			{#each res.plugins as p (p.name)}
				<tr>
					<td><strong>{p.name}</strong> <span class="badge {p.enabled ? 'green' : 'gray'}">{p.enabled ? $t('clusterx.enabled') : $t('clusterx.disabled')}</span></td>
					<td>{p.version}</td><td>{p.author} <small>({p.license})</small></td>
					<td>{#each p.manifest.permissions as perm}<code>{perm}</code> {/each}</td>
					<td><code>{p.signer}</code></td>
					<td>
						<button class="btn ghost" onclick={() => toggle(p)}>{p.enabled ? $t('clusterx.disable') : $t('clusterx.enable')}</button>
						{#if p.ui_url}<button class="btn ghost" onclick={() => (open = open === p.ui_url ? '' : p.ui_url)}>{$t('clusterx.open')}</button>{/if}
						<button class="btn ghost" onclick={() => remove(p)}>{$t('common.delete')}</button>
					</td>
				</tr>
			{:else}
				<tr><td colspan="6"><small>{$t('clusterx.no_plugins')}</small></td></tr>
			{/each}
		</tbody>
	</table>
	{#if open}<iframe class="pframe" title={$t('tools.plugins')} src={open} sandbox="allow-scripts allow-forms"></iframe>{/if}
</section>

<section class="card">
	<h3>{$t('clusterx.install')}</h3>
	<p><small>{$t('clusterx.install_help')}</small></p>
	<input type="file" accept=".tar.gz,.tgz,application/gzip" onchange={pick} disabled={busy} aria-label={$t('clusterx.install')} />
	{#if review}
		<div class="review">
			<h4>{$t('clusterx.review')}: {review.manifest.name} {review.manifest.version}</h4>
			<p>{review.manifest.description ?? ''}</p>
			<p><small>{$t('clusterx.review_meta', { author: review.manifest.author, license: review.manifest.license, signer: review.signer, files: review.files })}</small></p>
			<ul>
				{#each review.capabilities as c}<li><code>{c.permission}</code> — {c.description}</li>{/each}
				{#each review.manifest.hooks ?? [] as h}<li>{$t('clusterx.hook_line', { url: h.url, events: h.events.join(', ') })}</li>{/each}
				{#each review.manifest.agent_actions ?? [] as a}<li>{$t('clusterx.action_line', { action: a })}</li>{/each}
			</ul>
			{#if review.upgrade}<p><span class="badge amber">{$t('clusterx.upgrade')}</span></p>{/if}
			<button class="btn" disabled={busy} onclick={install}>{$t('clusterx.install_confirm')}</button>
		</div>
	{/if}
</section>

<section class="card">
	<h3>{$t('clusterx.keys')}</h3>
	<table class="table">
		<thead><tr><th>{$t('clusterx.label')}</th><th>{$t('clusterx.key_id')}</th><th></th></tr></thead>
		<tbody>
			{#each res.keys as k (k.id)}
				<tr><td>{k.name}</td><td><code>{k.key_id}</code></td><td><button class="btn ghost" onclick={() => delKey(k)}>{$t('common.delete')}</button></td></tr>
			{:else}
				<tr><td colspan="3"><small>{$t('clusterx.no_keys')}</small></td></tr>
			{/each}
		</tbody>
	</table>
	<form class="bar" onsubmit={addKey}>
		<input bind:value={key.name} placeholder={$t('clusterx.label')} aria-label={$t('clusterx.label')} required maxlength="64" />
		<input bind:value={key.pubkey} placeholder={$t('clusterx.pubkey')} aria-label={$t('clusterx.pubkey')} required class="wide" />
		<button class="btn">{$t('clusterx.trust')}</button>
	</form>
	<p><small>{$t('clusterx.keys_help')}</small></p>
</section>
{/if}

<style>
	.bar { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin-top: 8px; }
	.wide { min-width: 320px; flex: 1; }
	.review { margin-top: 12px; padding: 12px; border: 1px solid var(--border, #ddd); border-radius: 8px; }
	.pframe { width: 100%; height: 420px; border: 1px solid var(--border, #ddd); border-radius: 8px; margin-top: 12px; }
</style>
