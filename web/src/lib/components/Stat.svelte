<script>
	import { AlertTriangle } from '@lucide/svelte';
	import { t, fmt } from '$lib/i18n/index.js';
	import { isUnlimited } from '$lib/limits.js';
	let { label, used = 0, limit = 0, bytes = false } = $props();
	// G1: null/-1 (and 0 on servers that predate the round-2 contract) mean unlimited
	let unl = $derived(isUnlimited(limit));
	let pct = $derived(unl ? 0 : limit > 0 ? Math.min(100, (used / limit) * 100) : used > 0 ? 100 : 0);
	let show = (v) => (bytes ? $fmt.bytes(v) : $fmt.num(v));
</script>

<div class="stat">
	<div class="row">
		<span class="grow lbl">{label}</span>
		{#if pct >= 80}<AlertTriangle size={14} color="var(--amber)" aria-hidden="true" />{/if}
	</div>
	<div class="val">
		<b>{show(used)}</b> <span class="muted">/ {unl ? '∞' : show(limit)}</span>
	</div>
	<div class="progress" class:warn={pct >= 80 && pct < 95} class:crit={pct >= 95} role="progressbar" aria-label={label} aria-valuemin="0" aria-valuemax="100" aria-valuenow={Math.round(pct)}><div style="width:{unl ? 0 : Math.max(pct, 2)}%"></div></div>
</div>

<style>
	.stat { padding: 10px 0; border-bottom: 1px solid var(--border); }
	.stat:last-child { border-bottom: 0; }
	.lbl { font-size: 12.5px; color: var(--muted); }
	.val { margin: 2px 0 6px; font-size: 13.5px; }
</style>
