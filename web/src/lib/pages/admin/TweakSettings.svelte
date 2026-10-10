<script>
	// v1.1: Tweak Settings — typed, allowlisted server settings and per-tool switches.
	import { SlidersHorizontal, Save } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t } from '$lib/i18n/index.js';
	import { showErr, ok } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';
	let items = $state([]);
	let vals = $state({});
	async function load() {
		try { items = (await api.get('/admin/tweak-settings')).settings; vals = Object.fromEntries(items.map((i) => [i.key, i.value])); } catch (e) { showErr(e); }
	}
	let groups = $derived([...new Set(items.map((i) => i.group))]);
	async function save(e) {
		e.preventDefault();
		const changed = Object.fromEntries(items.filter((i) => String(vals[i.key]) !== i.value).map((i) => [i.key, String(vals[i.key])]));
		if (!Object.keys(changed).length) return;
		try { items = (await api.put('/admin/tweak-settings', { values: changed })).settings; vals = Object.fromEntries(items.map((i) => [i.key, i.value])); ok('v11.saved'); } catch (err) { showErr(err); }
	}
	const name = (k) => { const key = 'v11.tw_' + k; const s = $t(key); return s === key ? k : s; };
</script>

<PageHead title={$t('tools.tweak_settings')} desc={$t('v11.tweak_desc')} icon={SlidersHorizontal} />
<form class="stack" onsubmit={save}>
	{#each groups as g}
		<div class="card"><div class="card-head"><h2>{$t('v11.twg_' + g)}</h2></div><div class="card-body stack">
			{#each items.filter((i) => i.group === g) as i (i.key)}
				<div class="row wraprow">
					<span class="lbl">{name(i.key)} <span class="muted small mono">{i.key}</span></span>
					{#if i.kind === 'bool'}
						<label class="check"><input type="checkbox" checked={vals[i.key] === '1'} onchange={(e) => (vals[i.key] = e.currentTarget.checked ? '1' : '0')} /> {$t('v11.on')}</label>
					{:else if i.kind === 'int'}
						<input type="number" min={i.min} max={i.max} bind:value={vals[i.key]} aria-label={i.key} /> <span class="muted small">{i.min}–{i.max}</span>
					{:else if i.kind === 'enum'}
						<select bind:value={vals[i.key]} aria-label={i.key}>{#each i.options as o}<option value={o}>{o}</option>{/each}</select>
					{:else}
						<input bind:value={vals[i.key]} maxlength="64" aria-label={i.key} />
					{/if}
					<span class="muted small">{$t('v11.default')}: {i.default}</span>
				</div>
			{/each}
		</div></div>
	{/each}
	<div><button class="btn primary"><Save size={14} /> {$t('common.save')}</button></div>
</form>

<style>.wraprow { flex-wrap: wrap; align-items: center; gap: 12px; } .lbl { min-width: 280px; } .check { display: flex; gap: 6px; align-items: center; }</style>
