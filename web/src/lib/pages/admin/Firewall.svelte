<script>
	import { Ban, Plus, Trash2, RotateCcw, ShieldCheck } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t } from '$lib/i18n/index.js';
	import { showErr, ok, ask } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';
	import Modal from '$lib/components/Modal.svelte';

	let tab = $state('rules');
	let status = $state(null);
	let rules = $state([]);
	let history = $state([]);
	let blocks = $state([]);
	let waf = $state(null);
	let busy = $state(false);
	let ruleOpen = $state(false);
	let rule = $state(null);
	let blk = $state({ ip: '', reason: '', timeout_seconds: 3600 });
	let pending = $state(null); // {version, token, deadline}
	let left = $state(0);
	let timer;
	let wafEdit = $state(null);
	let wafOpen = $state(false);

	async function load() {
		try {
			const [s, r, h, b] = await Promise.all([
				api.get('/admin/firewall/status'),
				api.get('/admin/firewall/rules'),
				api.get('/admin/firewall/history'),
				api.get('/admin/firewall/blocks')
			]);
			status = s; rules = r.rules ?? []; history = h.history ?? []; blocks = b.blocks ?? [];
			waf = await api.get('/admin/waf').catch(() => null);
		} catch (e) { showErr(e); }
	}
	load();

	function newRule() { rule = { action: 'allow', cidr: '', proto: 'tcp', ports: '', rate_per_min: 0, comment: '' }; ruleOpen = true; }
	function editRule(r) { rule = { ...r, ports: (r.ports ?? []).join(','), proto: r.proto || 'tcp' }; ruleOpen = true; }
	async function saveRule(e) {
		e.preventDefault();
		busy = true;
		const body = { action: rule.action, cidr: rule.cidr.trim(), comment: rule.comment || '' };
		const ports = String(rule.ports || '').split(',').map((x) => Number(x.trim())).filter((x) => x > 0);
		if (ports.length) { body.ports = ports; body.proto = rule.proto; }
		if (rule.action === 'ratelimit') body.rate_per_min = Number(rule.rate_per_min) || 0;
		try {
			if (rule.id) await api.put(`/admin/firewall/rules/${rule.id}`, body); else await api.post('/admin/firewall/rules', body);
			ruleOpen = false; ok('netsec.saved'); load();
		} catch (err) { showErr(err); }
		busy = false;
	}
	async function delRule(r) {
		if (!ask('netsec.confirm_delete_rule', { cidr: r.cidr || '*' })) return;
		try { await api.del(`/admin/firewall/rules/${r.id}`); load(); } catch (e) { showErr(e); }
	}

	function startCountdown(res) {
		if (res.status !== 'pending') { showErr({ code: res.reason || 'fw_apply_failed' }); load(); return; }
		pending = res;
		const end = new Date(res.deadline).getTime();
		clearInterval(timer);
		const tick = () => {
			left = Math.max(0, Math.round((end - Date.now()) / 1000));
			if (left <= 0) { clearInterval(timer); pending = null; ok('netsec.rolled_back'); load(); }
		};
		tick();
		timer = setInterval(tick, 1000);
	}
	async function apply() {
		if (!ask('netsec.confirm_apply')) return;
		busy = true;
		try { startCountdown(await api.post('/admin/firewall/apply', {})); } catch (e) { showErr(e); }
		busy = false;
	}
	async function rollbackTo(v) {
		if (!ask('netsec.confirm_rollback', { v })) return;
		busy = true;
		try { startCountdown(await api.post(`/admin/firewall/rollback/${v}`, {})); } catch (e) { showErr(e); }
		busy = false;
	}
	async function confirm() {
		try {
			await api.post('/admin/firewall/confirm', { version: pending.version, token: pending.token });
			clearInterval(timer); pending = null; ok('netsec.confirmed'); load();
		} catch (e) { clearInterval(timer); pending = null; showErr(e); load(); }
	}
	async function addBlock(e) {
		e.preventDefault();
		try {
			const r = await api.post('/admin/firewall/blocks', { ip: blk.ip.trim(), reason: blk.reason, timeout_seconds: Number(blk.timeout_seconds) });
			ok(r.status === 'ok' ? 'netsec.blocked' : 'netsec.blocked_db_only'); blk.ip = ''; blk.reason = ''; load();
		} catch (err) { showErr(err); }
	}
	async function delBlock(b) {
		try { await api.del(`/admin/firewall/blocks/${b.id}`); load(); } catch (e) { showErr(e); }
	}
	function editWaf(d) { wafEdit = { domain: d.domain, mode: d.mode, exclusions: (d.exclusions ?? []).join(', ') }; wafOpen = true; }
	async function saveWaf(e) {
		e.preventDefault();
		busy = true;
		const exclusions = wafEdit.exclusions.split(/[\s,]+/).filter(Boolean);
		try {
			const r = await api.put(`/admin/waf/${encodeURIComponent(wafEdit.domain)}`, { mode: wafEdit.mode, exclusions });
			wafOpen = false;
			ok(r.status === 'applied' ? (r.wired ? 'netsec.waf_applied' : 'netsec.waf_not_wired') : 'netsec.waf_saved_not_installed');
			load();
		} catch (err) { showErr(err); }
		busy = false;
	}
	const when = (u) => (u ? new Date(u * 1000).toLocaleString() : '—');
</script>

<PageHead title={$t('netsec.title')} desc={$t('netsec.desc')} icon={Ban}>
	{#snippet actions()}<button class="btn primary" disabled={busy || !!pending} onclick={apply}><ShieldCheck size={15} /> {$t('netsec.apply')}</button>{/snippet}
</PageHead>
{#if status && !status.supported}<div class="card pad warn" role="status">{$t('netsec.unsupported', { reason: status.reason || '' })}</div>{/if}
{#if status}<p class="small muted">{$t('netsec.client_ip', { ip: status.client_ip, v: status.current_version || '—' })}</p>{/if}

<div class="tabs" role="tablist">
	{#each ['rules', 'blocks', 'history', 'waf'] as k}
		<button role="tab" class="btn ghost sm" class:active={tab === k} aria-selected={tab === k} onclick={() => (tab = k)}>{$t('netsec.tab.' + k)}</button>
	{/each}
</div>

{#if tab === 'rules'}
	<div class="card tw">
		<table class="table">
			<thead><tr><th>{$t('netsec.action')}</th><th>{$t('netsec.cidr')}</th><th>{$t('netsec.ports')}</th><th>{$t('netsec.comment')}</th><th></th></tr></thead>
			<tbody>
				{#each rules as r (r.id)}
					<tr><td>{$t('netsec.act.' + r.action)}</td><td><code>{r.cidr || '*'}</code></td><td>{(r.ports ?? []).join(', ') || '—'}{r.proto && r.ports?.length ? ' / ' + r.proto : ''}</td><td>{r.comment}</td>
						<td class="right"><button class="btn ghost sm" onclick={() => editRule(r)}>{$t('common.edit')}</button><button class="btn ghost sm" aria-label={$t('common.delete')} onclick={() => delRule(r)}><Trash2 size={14} /></button></td></tr>
				{:else}<tr><td colspan="5" class="empty">{$t('netsec.no_rules')}</td></tr>{/each}
			</tbody>
		</table>
	</div>
	<button class="btn" onclick={newRule}><Plus size={15} /> {$t('netsec.add_rule')}</button>
	<p class="small muted">{$t('netsec.rules_help')}</p>
{:else if tab === 'blocks'}
	<form class="card pad row" onsubmit={addBlock}>
		<label class="field"><span>{$t('netsec.ip')}</span><input bind:value={blk.ip} required maxlength="64" /></label>
		<label class="field"><span>{$t('netsec.reason')}</span><input bind:value={blk.reason} maxlength="200" /></label>
		<label class="field"><span>{$t('netsec.duration')}</span>
			<select bind:value={blk.timeout_seconds}><option value={3600}>1h</option><option value={86400}>24h</option><option value={604800}>7d</option><option value={2592000}>30d</option></select></label>
		<button class="btn primary">{$t('netsec.block')}</button>
	</form>
	<div class="card tw">
		<table class="table">
			<thead><tr><th>{$t('netsec.ip')}</th><th>{$t('netsec.reason')}</th><th>{$t('netsec.source')}</th><th>{$t('netsec.expires')}</th><th></th></tr></thead>
			<tbody>
				{#each blocks as b (b.id)}
					<tr><td><code>{b.ip}</code></td><td>{b.reason}</td><td>{b.source}</td><td>{when(b.expires_at)}</td><td class="right"><button class="btn ghost sm" onclick={() => delBlock(b)}>{$t('netsec.unblock')}</button></td></tr>
				{:else}<tr><td colspan="5" class="empty">{$t('netsec.no_blocks')}</td></tr>{/each}
			</tbody>
		</table>
	</div>
{:else if tab === 'history'}
	<div class="card tw">
		<table class="table">
			<thead><tr><th>{$t('netsec.version')}</th><th>{$t('netsec.status')}</th><th>{$t('netsec.rules')}</th><th>{$t('netsec.by')}</th><th>{$t('netsec.when')}</th><th></th></tr></thead>
			<tbody>
				{#each history as h (h.version)}
					<tr><td>v{h.version}{h.rollback_of ? ` ← v${h.rollback_of}` : ''}</td><td>{$t('netsec.st.' + h.status)}{h.reason ? ` (${h.reason})` : ''}</td><td>{h.rules}</td><td>{h.applied_by}</td><td>{when(h.created_at)}</td>
						<td class="right">{#if h.status === 'confirmed'}<button class="btn ghost sm" disabled={busy || !!pending} onclick={() => rollbackTo(h.version)}><RotateCcw size={14} /> {$t('netsec.rollback')}</button>{/if}</td></tr>
				{:else}<tr><td colspan="6" class="empty">{$t('netsec.no_history')}</td></tr>{/each}
			</tbody>
		</table>
	</div>
{:else}
	{#if waf?.provider && waf.provider.status !== 'installed'}<div class="card pad warn" role="status">{$t('netsec.waf_not_installed', { reason: waf.provider.reason || waf.provider.status })}</div>{/if}
	<p class="small muted">{$t('netsec.waf_help')}</p>
	<div class="card tw">
		<table class="table">
			<thead><tr><th>{$t('netsec.domain')}</th><th>{$t('netsec.mode')}</th><th>{$t('netsec.exclusions')}</th><th>{$t('netsec.version')}</th><th>{$t('netsec.status')}</th><th></th></tr></thead>
			<tbody>
				{#each waf?.domains ?? [] as d (d.domain)}
					<tr><td>{d.domain}</td><td>{$t('netsec.wafmode.' + d.mode)}</td><td>{d.exclusions.join(', ') || '—'}</td><td>{d.version || '—'}</td><td>{d.status || '—'}</td>
						<td class="right"><button class="btn ghost sm" onclick={() => editWaf(d)}>{$t('common.edit')}</button></td></tr>
				{:else}<tr><td colspan="6" class="empty">{$t('netsec.no_domains')}</td></tr>{/each}
			</tbody>
		</table>
	</div>
{/if}

<Modal bind:open={ruleOpen} title={rule?.id ? $t('netsec.edit_rule') : $t('netsec.add_rule')}>
	{#if rule}
		<form id="fwr" onsubmit={saveRule}>
			<label class="field"><span>{$t('netsec.action')}</span>
				<select bind:value={rule.action}>{#each ['allow', 'deny', 'ratelimit'] as a}<option value={a}>{$t('netsec.act.' + a)}</option>{/each}</select></label>
			<label class="field"><span>{$t('netsec.cidr')}</span><input bind:value={rule.cidr} placeholder="203.0.113.0/24" maxlength="64" /></label>
			<label class="field"><span>{$t('netsec.ports')}</span><input bind:value={rule.ports} placeholder="80,443" /></label>
			<label class="field"><span>{$t('netsec.proto')}</span><select bind:value={rule.proto}><option value="tcp">TCP</option><option value="udp">UDP</option></select></label>
			{#if rule.action === 'ratelimit'}<label class="field"><span>{$t('netsec.rate')}</span><input type="number" min="1" bind:value={rule.rate_per_min} /></label>{/if}
			<label class="field"><span>{$t('netsec.comment')}</span><input bind:value={rule.comment} maxlength="64" /></label>
		</form>
	{/if}
	{#snippet footer()}<button class="btn" onclick={() => (ruleOpen = false)}>{$t('common.cancel')}</button><button class="btn primary" form="fwr" disabled={busy}>{$t('common.save')}</button>{/snippet}
</Modal>

<Modal open={!!pending} title={$t('netsec.confirm_title')}>
	<p role="alert">{$t('netsec.confirm_body', { s: left })}</p>
	{#snippet footer()}<button class="btn primary" onclick={confirm}>{$t('netsec.confirm_keep')}</button>{/snippet}
</Modal>

<Modal bind:open={wafOpen} title={$t('netsec.waf_edit', { domain: wafEdit?.domain ?? '' })}>
	{#if wafEdit}
		<form id="wafe" onsubmit={saveWaf}>
			<label class="field"><span>{$t('netsec.mode')}</span>
				<select bind:value={wafEdit.mode}>{#each ['audit', 'block', 'off'] as m}<option value={m}>{$t('netsec.wafmode.' + m)}</option>{/each}</select></label>
			<label class="field"><span>{$t('netsec.exclusions')}</span><input bind:value={wafEdit.exclusions} placeholder="942100, 920350" inputmode="numeric" /></label>
			<p class="small muted">{$t('netsec.exclusions_help')}</p>
		</form>
	{/if}
	{#snippet footer()}<button class="btn" onclick={() => (wafOpen = false)}>{$t('common.cancel')}</button><button class="btn primary" form="wafe" disabled={busy}>{$t('common.save')}</button>{/snippet}
</Modal>
