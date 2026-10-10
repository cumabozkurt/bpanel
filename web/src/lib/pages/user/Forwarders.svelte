<script>
	import { Forward, Plus, Trash2, AtSign } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t } from '$lib/i18n/index.js';
	import { showErr, ok, ask, qs } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';
	import Modal from '$lib/components/Modal.svelte';
	import { EMAIL_LOCAL_PATTERN } from '$lib/validate.js';
	import { maxLen } from '$lib/a11y.js';

	let list = $state([]);
	let domains = $state([]);
	let open = $state(qs('new') === '1');
	let busy = $state(false);
	let catchall = qs('catchall') === '1';
	let form = $state({ source: '', domain: '', destination: '', mode: 'address' });

	async function load() {
		try {
			list = await api.get('/user/email/forwarders');
			domains = (await api.get('/user/email/accounts')).domains;
			if (!form.domain) form.domain = domains[0] ?? '';
		} catch (e) { showErr(e); }
	}
	load();
	let fwd = $derived(list.filter((f) => !f.source.startsWith('@')));
	let defaults = $derived(list.filter((f) => f.source.startsWith('@')));

	function newFwd(isCatch) { form = { source: isCatch ? '*' : '', domain: domains[0] ?? '', destination: '', mode: 'address' }; open = true; }
	async function save(e) {
		e.preventDefault(); busy = true;
		const destination = form.mode === 'address' ? form.destination : form.mode;
		try { await api.post('/user/email/forwarders', { source: form.source.trim(), domain: form.domain, destination: destination.trim() }); ok('common.saved'); open = false; load(); }
		catch (err) { showErr(err); }
		busy = false;
	}
	async function del(f) {
		if (!ask('fwd.confirm_delete', { src: f.source, dst: f.destination })) return;
		try { await api.del('/user/email/forwarders/' + f.id); ok('common.deleted'); load(); } catch (err) { showErr(err); }
	}
	const destLabel = (d) => (d === ':fail:' ? $t('fwd.dest_fail') : d === ':blackhole:' ? $t('fwd.dest_blackhole') : d);
</script>

<PageHead title={catchall ? $t('tools.default_address') : $t('fwd.title')} desc={catchall ? $t('fwd.catchall_desc') : $t('fwd.desc')} icon={catchall ? AtSign : Forward}>
	{#snippet actions()}
		<button class="btn" onclick={() => newFwd(true)}><AtSign size={15} /> {$t('fwd.set_default')}</button>
		<button class="btn primary" onclick={() => newFwd(false)}><Plus size={16} /> {$t('fwd.add')}</button>
	{/snippet}
</PageHead>

<div class="stack">
	{#if !catchall}
	<section class="card">
		<div class="card-head"><Forward size={17} /><h2>{$t('fwd.forwarders')}</h2></div>
		<div class="tw"><table class="table">
			<thead><tr><th>{$t('fwd.address')}</th><th>{$t('fwd.forward_to')}</th><th><span class="sr-only">{$t('common.actions')}</span></th></tr></thead>
			<tbody>
				{#each fwd as f}
					<tr><td><b>{f.source}</b></td><td>{destLabel(f.destination)}</td><td><div class="actions"><button class="linkbtn danger" onclick={() => del(f)} aria-label={$t('fwd.delete_named', { src: f.source })}><Trash2 size={13} /> {$t('common.delete')}</button></div></td></tr>
				{:else}<tr><td colspan="3" class="empty">{$t('common.none')}</td></tr>{/each}
			</tbody>
		</table></div>
	</section>
	{/if}
	<section class="card">
		<div class="card-head"><AtSign size={17} /><h2>{$t('fwd.defaults')}</h2></div>
		<div class="tw"><table class="table">
			<thead><tr><th>{$t('domains.domain')}</th><th>{$t('fwd.unrouted_to')}</th><th><span class="sr-only">{$t('common.actions')}</span></th></tr></thead>
			<tbody>
				{#each defaults as f}
					<tr><td><b>{f.source.slice(1)}</b></td><td>{destLabel(f.destination)}</td><td><div class="actions"><button class="linkbtn danger" onclick={() => del(f)}><Trash2 size={13} /> {$t('fwd.remove_default')}</button></div></td></tr>
				{:else}<tr><td colspan="3" class="empty">{$t('fwd.no_defaults')}</td></tr>{/each}
			</tbody>
		</table></div>
	</section>
</div>

<Modal bind:open title={form.source === '*' ? $t('fwd.set_default') : $t('fwd.add')}>
	<form id="fw" onsubmit={save}>
		{#if form.source === '*'}
			<label class="field"><span>{$t('domains.domain')}</span><select bind:value={form.domain}>{#each domains as d}<option>{d}</option>{/each}</select></label>
		{:else}
			<label class="field"><span>{$t('fwd.address')}</span>
				<div class="input-group"><input id="fwd-src" bind:value={form.source} placeholder="sales" required pattern={EMAIL_LOCAL_PATTERN + '|.{64,}'} use:maxLen={63} data-err="errors.invalid_email_local" autocapitalize="off" spellcheck="false" aria-label={$t('fwd.address')} /><span class="addon">@</span><select bind:value={form.domain} style="width:auto;border-radius:0 6px 6px 0" aria-label={$t('domains.domain')}>{#each domains as d}<option>{d}</option>{/each}</select></div>
			</label>
		{/if}
		<fieldset class="field" style="border:0;padding:0;margin:0 0 12px">
			<legend style="font-weight:600;font-size:13px;margin-bottom:6px">{$t('fwd.destination')}</legend>
			<label class="r"><input type="radio" bind:group={form.mode} value="address" /> {$t('fwd.dest_address')}</label>
			{#if form.mode === 'address'}<input type="email" bind:value={form.destination} placeholder="user@example.com" required style="margin:6px 0 10px" aria-label={$t('fwd.dest_address')} />{/if}
			<label class="r"><input type="radio" bind:group={form.mode} value=":fail:" /> {$t('fwd.dest_fail')}</label>
			<label class="r"><input type="radio" bind:group={form.mode} value=":blackhole:" /> {$t('fwd.dest_blackhole')}</label>
		</fieldset>
	</form>
	{#snippet footer()}<button class="btn" onclick={() => (open = false)}>{$t('common.cancel')}</button><button class="btn primary" form="fw" disabled={busy}>{$t('common.save')}</button>{/snippet}
</Modal>

<style>.r { display: flex; gap: 8px; align-items: center; margin: 4px 0; }</style>
