<script>
	// v1.1: Email encryption — the account's GnuPG keyring (~/.gnupg): generate, import, export, delete.
	import { KeySquare, Plus, Download, Trash2, Upload } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t } from '$lib/i18n/index.js';
	import { showErr, ok, ask } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';
	let data = $state(null);
	let gen = $state({ name: '', email: '', comment: '', algo: 'ed25519', expire: '2y', passphrase: '' });
	let armored = $state('');
	let exported = $state(null);
	let busy = $state(false);
	async function load() { try { data = await api.get('/user/gpg'); } catch (e) { showErr(e); } }
	async function generate(e) {
		e.preventDefault(); busy = true;
		try { data = await api.post('/user/gpg/generate', gen); gen.passphrase = ''; ok('v11.gpg_generated'); } catch (err) { showErr(err); }
		busy = false;
	}
	async function importKey(e) {
		e.preventDefault(); busy = true;
		try { data = await api.post('/user/gpg/import', { armored }); armored = ''; ok('v11.gpg_imported'); } catch (err) { showErr(err); }
		busy = false;
	}
	async function exp(k) { try { exported = { fpr: k.fingerprint, text: (await api.get('/user/gpg/' + k.fingerprint + '/export')).armored }; } catch (e) { showErr(e); } }
	async function del(k) {
		if (!ask('v11.gpg_delete_confirm', { id: k.key_id })) return;
		try { data = await api.del('/user/gpg/' + k.fingerprint); ok('v11.deleted'); } catch (e) { showErr(e); }
	}
	const day = (u) => (u ? new Date(u * 1000).toLocaleDateString() : '—');
	load();
</script>

<PageHead title={$t('tools.encryption')} desc={$t('v11.gpg_desc')} icon={KeySquare} />
<div class="stack">
	{#if data?.status === 'not_installed'}<div class="card pad"><p>{$t('v11.not_installed')} <span class="muted small">{data.reason}</span></p></div>{/if}
	{#if data}
		<div class="card tw"><table class="table">
			<thead><tr><th>{$t('v11.key_id')}</th><th>{$t('v11.uids')}</th><th>{$t('v11.algo')}</th><th>{$t('v11.created')}</th><th>{$t('v11.expires')}</th><th></th></tr></thead>
			<tbody>
				{#each data.keys ?? [] as k (k.fingerprint)}
					<tr><td class="mono small">{k.key_id}{#if k.secret} <span class="badge green">{$t('v11.secret')}</span>{/if}</td><td>{k.uids.join(', ')}</td><td>{k.algo}{k.bits ? ' ' + k.bits : ''}</td><td>{day(k.created)}</td><td>{day(k.expires)}</td>
						<td class="right"><button class="btn sm" onclick={() => exp(k)}><Download size={14} /> {$t('v11.export')}</button>
							<button class="btn ghost sm" aria-label={$t('common.delete')} onclick={() => del(k)}><Trash2 size={14} /></button></td></tr>
				{:else}<tr><td colspan="6" class="empty">{$t('v11.gpg_none')}</td></tr>{/each}
			</tbody></table></div>
	{/if}
	{#if exported}<div class="card pad"><p class="small muted">{exported.fpr}</p><textarea class="mono" rows="10" readonly style="width:100%">{exported.text}</textarea></div>{/if}
	<form class="card" onsubmit={generate}><div class="card-head"><Plus size={17} /><h2>{$t('v11.gpg_generate')}</h2></div><div class="card-body stack">
		<div class="row wraprow">
			<label class="field"><span>{$t('v11.name')}</span><input bind:value={gen.name} required maxlength="80" /></label>
			<label class="field"><span>{$t('newacc.email')}</span><input type="email" bind:value={gen.email} required maxlength="254" /></label>
			<label class="field"><span>{$t('v11.comment')}</span><input bind:value={gen.comment} maxlength="80" /></label>
		</div>
		<div class="row wraprow">
			<label class="field"><span>{$t('v11.algo')}</span><select bind:value={gen.algo}><option value="ed25519">Ed25519</option><option value="rsa3072">RSA 3072</option><option value="rsa4096">RSA 4096</option></select></label>
			<label class="field"><span>{$t('v11.expires')}</span><select bind:value={gen.expire}><option value="1y">1y</option><option value="2y">2y</option><option value="5y">5y</option><option value="0">{$t('v11.never')}</option></select></label>
			<label class="field"><span>{$t('v11.passphrase')}</span><input type="password" bind:value={gen.passphrase} maxlength="256" autocomplete="new-password" /></label>
		</div>
		<div><button class="btn primary" disabled={busy}>{$t('v11.gpg_generate')}</button></div>
	</div></form>
	<form class="card" onsubmit={importKey}><div class="card-head"><Upload size={17} /><h2>{$t('v11.gpg_import')}</h2></div><div class="card-body stack">
		<textarea class="mono" rows="6" bind:value={armored} required placeholder="-----BEGIN PGP PUBLIC KEY BLOCK-----"></textarea>
		<div><button class="btn primary" disabled={busy}>{$t('v11.gpg_import')}</button></div>
	</div></form>
</div>

<style>.wraprow { flex-wrap: wrap; align-items: flex-end; gap: 12px; }</style>
