<script>
	// v1.1: SSH key manager — ~/.ssh keys and authorized_keys of the account.
	import { KeyRound, Plus, Upload, Trash2, ShieldCheck, ShieldOff } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t } from '$lib/i18n/index.js';
	import { showErr, ok, ask } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';
	let keys = $state([]);
	let gen = $state({ name: 'id_ed25519', type: 'ed25519', bits: 4096, passphrase: '', authorize: true });
	let imp = $state({ name: '', public_key: '', private_key: '', authorize: true });
	let priv = $state(null);
	let busy = $state(false);
	async function load() { try { keys = (await api.get('/user/ssh-keys')).keys ?? []; } catch (e) { showErr(e); } }
	async function generate(e) {
		e.preventDefault(); busy = true;
		try {
			const body = { name: gen.name, type: gen.type, passphrase: gen.passphrase, authorize: gen.authorize };
			if (gen.type === 'rsa') body.bits = Number(gen.bits);
			const r = await api.post('/user/ssh-keys/generate', body);
			priv = { name: r.key.name, text: r.private_key };
			gen.passphrase = '';
			load();
		} catch (err) { showErr(err); }
		busy = false;
	}
	async function importKey(e) {
		e.preventDefault(); busy = true;
		try { await api.post('/user/ssh-keys/import', imp); imp = { name: '', public_key: '', private_key: '', authorize: true }; ok('v11.ssh_imported'); load(); } catch (err) { showErr(err); }
		busy = false;
	}
	async function auth(k, on) { try { await api.post('/user/ssh-keys/' + encodeURIComponent(k.name) + '/authorize', { authorize: on }); load(); } catch (e) { showErr(e); } }
	async function del(k) {
		if (!ask('v11.ssh_delete_confirm', { name: k.name })) return;
		try { await api.del('/user/ssh-keys/' + encodeURIComponent(k.name)); ok('v11.deleted'); load(); } catch (e) { showErr(e); }
	}
	load();
</script>

<PageHead title={$t('tools.ssh_keys')} desc={$t('v11.ssh_desc')} icon={KeyRound} />
<div class="stack">
	{#if priv}
		<div class="card pad" role="status"><p><strong>{priv.name}</strong> — {$t('v11.ssh_private_once')}</p>
			<textarea class="mono" rows="8" readonly style="width:100%">{priv.text}</textarea>
			<button class="btn sm" onclick={() => (priv = null)}>{$t('v11.done')}</button></div>
	{/if}
	<div class="card tw"><table class="table">
		<thead><tr><th>{$t('v11.name')}</th><th>{$t('v11.algo')}</th><th>{$t('v11.fingerprint')}</th><th>{$t('v11.status')}</th><th></th></tr></thead>
		<tbody>
			{#each keys as k (k.name)}
				<tr><td class="mono">{k.name}{#if k.has_private} <span class="badge">{$t('v11.private')}</span>{/if}</td><td>{k.type}{k.bits ? ' ' + k.bits : ''}</td><td class="mono small">{k.fingerprint}</td>
					<td><span class="badge" class:green={k.authorized}>{k.authorized ? $t('v11.authorized') : $t('v11.not_authorized')}</span></td>
					<td class="right">
						{#if k.authorized}<button class="btn sm" onclick={() => auth(k, false)}><ShieldOff size={14} /> {$t('v11.deauthorize')}</button>
						{:else}<button class="btn sm" onclick={() => auth(k, true)}><ShieldCheck size={14} /> {$t('v11.authorize')}</button>{/if}
						<button class="btn ghost sm" aria-label={$t('common.delete')} onclick={() => del(k)}><Trash2 size={14} /></button></td></tr>
			{:else}<tr><td colspan="5" class="empty">{$t('v11.ssh_none')}</td></tr>{/each}
		</tbody></table></div>
	<form class="card" onsubmit={generate}><div class="card-head"><Plus size={17} /><h2>{$t('v11.ssh_generate')}</h2></div><div class="card-body stack">
		<div class="row wraprow">
			<label class="field"><span>{$t('v11.name')}</span><input class="mono" bind:value={gen.name} required maxlength="64" pattern="[A-Za-z0-9._\-]+" /></label>
			<label class="field"><span>{$t('v11.algo')}</span><select bind:value={gen.type}><option value="ed25519">Ed25519</option><option value="rsa">RSA</option></select></label>
			{#if gen.type === 'rsa'}<label class="field"><span>{$t('v11.bits')}</span><select bind:value={gen.bits}><option value={3072}>3072</option><option value={4096}>4096</option></select></label>{/if}
			<label class="field"><span>{$t('v11.passphrase')}</span><input type="password" bind:value={gen.passphrase} maxlength="256" autocomplete="new-password" /></label>
		</div>
		<label class="check"><input type="checkbox" bind:checked={gen.authorize} /> {$t('v11.authorize_now')}</label>
		<div><button class="btn primary" disabled={busy}>{$t('v11.ssh_generate')}</button></div>
	</div></form>
	<form class="card" onsubmit={importKey}><div class="card-head"><Upload size={17} /><h2>{$t('v11.ssh_import')}</h2></div><div class="card-body stack">
		<label class="field" style="max-width:320px"><span>{$t('v11.name')}</span><input class="mono" bind:value={imp.name} required maxlength="64" pattern="[A-Za-z0-9._\-]+" /></label>
		<label class="field"><span>{$t('v11.public_key')}</span><textarea class="mono" rows="3" bind:value={imp.public_key} required placeholder="ssh-ed25519 AAAA… user@host"></textarea></label>
		<label class="field"><span>{$t('v11.private_key_optional')}</span><textarea class="mono" rows="4" bind:value={imp.private_key}></textarea></label>
		<label class="check"><input type="checkbox" bind:checked={imp.authorize} /> {$t('v11.authorize_now')}</label>
		<div><button class="btn primary" disabled={busy}>{$t('v11.ssh_import')}</button></div>
	</div></form>
</div>

<style>.wraprow { flex-wrap: wrap; align-items: flex-end; gap: 12px; } .check { display: flex; gap: 8px; align-items: center; }</style>
