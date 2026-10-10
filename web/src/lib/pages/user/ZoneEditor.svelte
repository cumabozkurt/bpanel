<script>
	import { Network, Plus, Trash2, Pencil, RotateCcw } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t } from '$lib/i18n/index.js';
	import { showErr, ok, ask, qs, errText } from '$lib/util.js';
	import { customValidity } from '$lib/a11y.js';
	import { dnsName, dnsRecordProblem, dnsCompose, dnsParse, blankRecord, byteLen } from '$lib/validate.js';
	import PageHead from '$lib/components/PageHead.svelte';
	import Modal from '$lib/components/Modal.svelte';
	import Pager from '$lib/components/Pager.svelte';

	let { params } = $props();
	let zone = $state(null);
	let loadError = $state(null); // R2-UX-39: reading a zone failed (not a rejected change)
	let filter = $state('');
	let search = $state('');
	let open = $state(false);
	let busy = $state(false);
	let tried = $state(false);
	const types = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'SRV', 'CAA'];
	const help = { A: '203.0.113.10', AAAA: '2001:db8::10', CNAME: 'target.example.com', TXT: 'v=spf1 +a +mx ~all' };
	let form = $state({ name: '', type: 'A', ttl: 3600, records: [{ value: '' }], editing: false });

	// Server-side paging (R2-PERF / v0.3): the API filters (q, type) and pages the records; a page is
	// grouped into record sets here. Editing always re-reads the whole set, so a set split across two
	// pages is never saved with only half of its values.
	let pg = $state({ pageNo: 1, size: 50, total: 0 });
	const srv = {
		get total() { return pg.total; }, get size() { return pg.size; }, get pageNo() { return pg.pageNo; },
		get pages() { return Math.max(1, Math.ceil(pg.total / pg.size)); },
		get from() { return pg.total ? (pg.pageNo - 1) * pg.size + 1 : 0; },
		get to() { return Math.min(pg.total, pg.pageNo * pg.size); },
		go(n) { pg.pageNo = n; load(); },
		setSize(n) { pg.size = n; pg.pageNo = 1; load(); }
	};
	let seq = 0;
	async function load() {
		const my = ++seq;
		const q = new URLSearchParams({ limit: String(pg.size), offset: String((pg.pageNo - 1) * pg.size) });
		if (filter) q.set('type', filter);
		if (search.trim()) q.set('q', search.trim());
		try {
			const r = await api.page('/user/dns/' + params.domain + '?' + q);
			if (my !== seq) return;
			zone = r.data; pg.total = r.total ?? r.data?.total ?? (r.data?.records?.length || 0); loadError = null;
		} catch (e) { if (my === seq) { zone = null; loadError = e; } }
	}
	let tmr;
	$effect(() => { filter; search; clearTimeout(tmr); tmr = setTimeout(() => { pg.pageNo = 1; load(); }, search ? 250 : 0); return () => clearTimeout(tmr); });

	// group into rrsets
	let allSets = $derived.by(() => {
		const m = new Map();
		for (const r of zone?.records ?? []) {
			const k = r.name + '|' + r.type;
			if (!m.has(k)) m.set(k, { name: r.name, type: r.type, ttl: r.ttl, records: [] });
			m.get(k).records.push(r.content);
		}
		return [...m.values()];
	});
	let sets = $derived(allSets);

	function short(n) { return n === params.domain ? '@' : n.replace('.' + params.domain, ''); }
	function add(type = 'A') { form = { name: '', type, ttl: 3600, records: [blankRecord(type)], editing: false }; tried = false; open = true; }
	async function editSet(s) {
		let recs = s.records;
		try {
			const full = await api.get('/user/dns/' + params.domain + '?' + new URLSearchParams({ type: s.type, q: s.name }));
			const all = (full?.records ?? []).filter((r) => r.name === s.name && r.type === s.type).map((r) => r.content);
			if (all.length) recs = all;
		} catch (err) { showErr(err); return; }
		form = { name: short(s.name), type: s.type, ttl: s.ttl, records: recs.map((c) => dnsParse(s.type, c)), editing: true };
		tried = false;
		open = true;
	}
	// G2: quick add from the zone list (/dns/<zone>?add=MX)
	const addParam = qs('add');
	if (addParam && types.includes(addParam)) add(addParam);
	function setType(ty) {
		if (ty === form.type) return;
		form.type = ty;
		form.records = form.records.map(() => blankRecord(ty));
	}

	// R2-UX-18: a trailing dot makes a name absolute; IDN labels are converted; the final name is shown
	let nm = $derived(dnsName(form.name, params.domain));
	let recProblems = $derived(form.records.map((r) => dnsRecordProblem(form.type, r)));
	let ttlProblem = $derived(!/^\d+$/.test(String(form.ttl)) || form.ttl < 60 || form.ttl > 604800 ? 'val.dns_ttl' : null);
	let hasProblem = $derived(!!nm.problem || !!ttlProblem || recProblems.some(Boolean));

	async function save(e) {
		e.preventDefault();
		tried = true;
		if (hasProblem) { document.querySelector('#rr [aria-invalid="true"]')?.focus(); return; }
		busy = true;
		try {
			await api.put('/user/dns/' + params.domain + '/rrset', { name: nm.rel, type: form.type, ttl: Number(form.ttl), records: form.records.map((r) => dnsCompose(form.type, r)).filter(Boolean) });
			ok('dns.saved');
			open = false;
			load();
		} catch (err) { showErr(err); }
		busy = false;
	}
	async function del(s) {
		if (!ask('dns.confirm_delete', { name: s.name, type: s.type })) return;
		try { await api.del(`/user/dns/${params.domain}/rrset/${encodeURIComponent(s.name)}/${s.type}`); ok('dns.deleted'); load(); } catch (err) { showErr(err); }
	}
	async function reset() {
		if (!ask('dns.confirm_reset', { zone: params.domain })) return;
		try { await api.post('/user/dns/' + params.domain + '/reset'); ok('dns.reset_done'); load(); } catch (err) { showErr(err); }
	}
	const locked = (s) => s.type === 'SOA' || (s.type === 'NS' && s.name === params.domain);
	const nonAscii = (v) => /[^\x00-\x7f]/.test(v ?? '');
</script>

<PageHead title={$t('dns.title', { zone: params.domain })} desc={$t('dns.desc')} icon={Network} back="/dns" backLabel={$t('tools.zone_editor')}>
	{#snippet actions()}
		<button class="btn" onclick={reset}><RotateCcw size={15} /> {$t('dns.reset')}</button>
		<button class="btn primary" onclick={() => add()} disabled={!zone}><Plus size={16} /> {$t('dns.add_record')}</button>
	{/snippet}
</PageHead>

{#if loadError}
	<div class="alert error" role="alert"><div>
		<b>{$t(loadError.code === 'pdns_error' || loadError.code === 'zone_not_found' || loadError.status === 404 ? 'dns.zone_missing' : 'dns.load_failed')}</b>
		<div class="small">{errText(loadError)}</div>
		<div class="row" style="margin-top:8px"><button class="btn sm" onclick={load}>{$t('dns.retry')}</button><button class="btn sm" onclick={reset}><RotateCcw size={14} /> {$t('dns.reset')}</button></div>
	</div></div>
{/if}

<div class="card">
	<div class="toolbar">
		<input type="search" placeholder={$t('common.search')} bind:value={search} aria-label={$t('dns.search')} />
		<div class="chips" role="group" aria-label={$t('dns.filter_type')}>
			<button class="chip" class:on={!filter} aria-pressed={!filter} onclick={() => (filter = '')}>{$t('common.all')}</button>
			{#each ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SRV', 'CAA'] as ty}<button class="chip" class:on={filter === ty} aria-pressed={filter === ty} onclick={() => (filter = ty)}>{ty}</button>{/each}
		</div>
		<span class="grow"></span>
		{#if zone?.serial}<span class="muted small">{$t('dns.serial')}: <span class="mono">{zone.serial}</span></span>{/if}
	</div>
	<div class="tw">
	<table class="table">
		<thead><tr><th>{$t('dns.name')}</th><th>TTL</th><th>{$t('dns.type')}</th><th>{$t('dns.record')}</th><th><span class="sr-only">{$t('common.actions')}</span></th></tr></thead>
		<tbody>
			{#each sets as s}
				<tr>
					<td class="mono">{s.name}</td>
					<td>{s.ttl}</td>
					<td><span class="badge blue">{s.type}</span></td>
					<td class="rec">{#each s.records as c}<div class="mono">{c}</div>{/each}</td>
					<td><div class="actions">
						{#if !locked(s)}
							<button class="linkbtn" onclick={() => editSet(s)} aria-label={$t('dns.edit_named', { name: s.name, type: s.type })}><Pencil size={13} /> {$t('common.edit')}</button>
							<button class="linkbtn danger" onclick={() => del(s)} aria-label={$t('dns.delete_named', { name: s.name, type: s.type })}><Trash2 size={13} /> {$t('common.delete')}</button>
						{:else}<span class="muted small">{$t('dns.managed')}</span>{/if}
					</div></td>
				</tr>
			{:else}
				<tr><td colspan="5" class="empty">{zone ? $t('common.none') : loadError ? '—' : $t('common.loading')}</td></tr>
			{/each}
		</tbody>
	</table>
	</div>
	<Pager tbl={srv} sizes={[50, 100, 200]} />
</div>

<Modal bind:open title={$t('dns.record_set')} width={680}>
	<form id="rr" onsubmit={save} novalidate>
		<div class="grid3">
			<label class="field"><span>{$t('dns.name')}</span><div class="input-group"><input id="rr-name" bind:value={form.name} placeholder="@" autocapitalize="off" spellcheck="false" disabled={form.editing}
				use:customValidity={nm.problem} aria-invalid={nm.problem && (tried || form.name) ? 'true' : undefined} aria-describedby="rr-name-h" /><span class="addon ellip">.{params.domain}</span></div>
				{#if nm.problem && (tried || form.name)}<small class="field-err" id="rr-name-h">{$t(nm.problem, { zone: params.domain })}</small>
				{:else}<small id="rr-name-h">{$t('dns.fqdn_preview', { fqdn: nm.fqdn })}</small>{/if}</label>
			<label class="field"><span>{$t('dns.type')}</span><select value={form.type} onchange={(e) => setType(e.currentTarget.value)} disabled={form.editing}>{#each types as ty}<option>{ty}</option>{/each}</select></label>
			<label class="field"><span>TTL</span><input type="number" min="60" max="604800" bind:value={form.ttl} use:customValidity={ttlProblem} aria-invalid={tried && ttlProblem ? 'true' : undefined} />
				{#if tried && ttlProblem}<small class="field-err">{$t(ttlProblem)}</small>{/if}</label>
		</div>
		<span class="lbl" id="rr-vals">{$t('dns.values')}</span>
		{#each form.records as r, i}
			{@const p = recProblems[i]}
			{@const bad = tried && p ? 'true' : undefined}
			<fieldset class="val" aria-labelledby="rr-vals">
				<legend class="sr-only">{$t('dns.value_n', { n: i + 1 })}</legend>
				<div class="row vrow">
					{#if form.type === 'MX'}
						<label class="sub w-num"><span>{$t('dns.priority')}</span><input type="number" min="0" max="65535" bind:value={r.priority} aria-invalid={bad} /></label>
						<label class="sub grow"><span>{$t('dns.mail_server')}</span><input bind:value={r.host} placeholder={'mail.' + params.domain} class="mono" autocapitalize="off" spellcheck="false" aria-invalid={bad} /></label>
					{:else if form.type === 'SRV'}
						<label class="sub w-num"><span>{$t('dns.priority')}</span><input type="number" min="0" max="65535" bind:value={r.priority} aria-invalid={bad} /></label>
						<label class="sub w-num"><span>{$t('dns.weight')}</span><input type="number" min="0" max="65535" bind:value={r.weight} aria-invalid={bad} /></label>
						<label class="sub w-num"><span>{$t('dns.port')}</span><input type="number" min="0" max="65535" bind:value={r.port} aria-invalid={bad} /></label>
						<label class="sub grow"><span>{$t('dns.target')}</span><input bind:value={r.host} placeholder={'sip.' + params.domain} class="mono" autocapitalize="off" spellcheck="false" aria-invalid={bad} /></label>
					{:else if form.type === 'CAA'}
						<label class="sub w-num"><span>{$t('dns.flag')}</span><input type="number" min="0" max="255" bind:value={r.flag} aria-invalid={bad} /></label>
						<label class="sub w-tag"><span>{$t('dns.tag')}</span><select bind:value={r.tag}><option value="issue">issue</option><option value="issuewild">issuewild</option><option value="iodef">iodef</option></select></label>
						<label class="sub grow"><span>{$t('dns.caa_value')}</span><input bind:value={r.value} placeholder={r.tag === 'iodef' ? 'mailto:security@' + params.domain : 'letsencrypt.org'} class="mono" autocapitalize="off" spellcheck="false" aria-invalid={bad} /></label>
					{:else}
						<input class="mono grow" bind:value={r.value} placeholder={help[form.type]} aria-label={$t('dns.value_n', { n: i + 1 })} autocapitalize="off" spellcheck="false" aria-invalid={bad} />
					{/if}
					{#if form.records.length > 1}<button type="button" class="btn sm ghost rm" aria-label={$t('dns.remove_value_n', { n: i + 1 })} onclick={() => form.records.splice(i, 1)}><Trash2 size={14} /></button>{/if}
				</div>
				{#if tried && p}<small class="field-err" role="alert">{$t(p)}</small>
				{:else if form.type === 'TXT' && byteLen(r.value) > 255}<small class="muted">{$t('dns.txt_split', { n: Math.ceil(byteLen(r.value) / 255) })}</small>
				{:else if form.type === 'TXT' && nonAscii(r.value)}<small class="muted">{$t('dns.txt_non_ascii')}</small>{/if}
			</fieldset>
		{/each}
		<button type="button" class="linkbtn" onclick={() => form.records.push(blankRecord(form.type))}><Plus size={13} /> {$t('dns.add_value')}</button>
	</form>
	{#snippet footer()}<button class="btn" onclick={() => (open = false)}>{$t('common.cancel')}</button><button class="btn primary" form="rr" disabled={busy}>{$t('common.save')}</button>{/snippet}
</Modal>

<style>
	.chips { display: flex; gap: 6px; flex-wrap: wrap; }
	.chip { border: 1px solid var(--border); background: var(--card); border-radius: 999px; padding: 2px 10px; font: inherit; font-size: 12px; cursor: pointer; color: var(--text-2); }
	.chip.on { background: var(--blue-soft); color: var(--blue-text); border-color: transparent; }
	.rec { max-width: 520px; word-break: break-all; }
	.lbl { display: block; font-weight: 600; font-size: 13px; margin-bottom: 5px; }
	.val { border: 0; padding: 0; margin: 0 0 10px; }
	.vrow { align-items: flex-end; flex-wrap: wrap; gap: 8px; }
	.sub span { display: block; font-size: 12px; color: var(--muted); margin-bottom: 3px; }
	.w-num { width: 96px; }
	.w-tag { width: 130px; }
	.rm { margin-bottom: 3px; }
	.ellip { max-width: 50%; overflow: hidden; text-overflow: ellipsis; }
	.toolbar input[type='search'] { max-width: 220px; }
</style>
