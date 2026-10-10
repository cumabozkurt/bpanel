<script>
	// Lightweight inline SVG line chart (no dependency). points: [{ts, v}]
	let { points = [], label = '', format = (v) => String(v), max = null } = $props();
	const W = 320, H = 90, P = 4;
	let top = $derived(Math.max(max ?? 0, ...points.map((p) => p.v), 1e-9));
	let t0 = $derived(points.length ? points[0].ts : 0);
	let t1 = $derived(points.length ? points[points.length - 1].ts : 1);
	let path = $derived(points.map((p, i) => {
		const x = P + (t1 === t0 ? 0 : ((p.ts - t0) / (t1 - t0)) * (W - 2 * P));
		const y = H - P - (p.v / top) * (H - 2 * P);
		return (i ? 'L' : 'M') + x.toFixed(1) + ' ' + y.toFixed(1);
	}).join(' '));
	let last = $derived(points.length ? points[points.length - 1].v : null);
	let peak = $derived(points.length ? Math.max(...points.map((p) => p.v)) : null);
</script>

<figure class="uchart">
	<figcaption class="small"><b>{label}</b> <span class="muted">{last === null ? '—' : format(last)}{peak !== null ? ' · max ' + format(peak) : ''}</span></figcaption>
	<svg viewBox="0 0 {W} {H}" width="100%" height={H} role="img" aria-label={label} preserveAspectRatio="none">
		<line x1={P} y1={H - P} x2={W - P} y2={H - P} stroke="currentColor" opacity="0.2" />
		{#if max}<line x1={P} y1={P} x2={W - P} y2={P} stroke="currentColor" opacity="0.25" stroke-dasharray="4 3" />{/if}
		{#if points.length > 1}<path d={path} fill="none" stroke="var(--accent, #2563eb)" stroke-width="1.6" vector-effect="non-scaling-stroke" />{/if}
	</svg>
</figure>

<style>
	.uchart { margin: 0; padding: 0.5rem; border: 1px solid var(--border, #ddd); border-radius: 8px; min-width: 0; }
	svg { display: block; overflow: visible; }
</style>
