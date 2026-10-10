<script>
	// Line icon with a turquoise accent disc behind it (our own "duotone" style).
	let { icon: Icon, size = 30 } = $props();
</script>

<span class="ti" style="--s:{size}px">
	<span class="disc"></span>
	<Icon size={size * 0.72} strokeWidth={1.6} />
</span>

<style>
	.ti { position: relative; display: inline-grid; place-items: center; width: var(--s); height: var(--s); color: var(--text); flex: none; }
	.ti :global(svg) { position: relative; }
	.disc { position: absolute; width: 58%; height: 58%; right: -6%; bottom: -4%; border-radius: 50%; background: var(--accent); opacity: 0.28; }
</style>
