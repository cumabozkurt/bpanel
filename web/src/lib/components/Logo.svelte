<script>
	// Original BOZKURT PANEL mark: a geometric wolf head.
	let { size = 30, word = true, light = true } = $props();
</script>

<span class="logo" style="--s:{size}px">
	<svg viewBox="0 0 64 64" width={size} height={size} aria-hidden="true">
		<rect width="64" height="64" rx="14" fill="#14B8A6" />
		<path d="M14 12l12 12h12l12-12-2 22-6 10-10 10-10-10-6-10z" fill="#0F172A" />
		<path d="M24 33l-5-4 8 2zM40 33l5-4-8 2z" fill="#14B8A6" />
		<path d="M28.5 45h7L32 49z" fill="#14B8A6" />
	</svg>
	{#if word}
		<span class="word" class:light><b>BOZKURT</b> PANEL</span>
	{/if}
</span>

<style>
	.logo { display: inline-flex; align-items: center; gap: 10px; }
	.word { font-size: calc(var(--s) * 0.5); letter-spacing: 0.08em; color: var(--text); white-space: nowrap; }
	.word.light { color: #fff; }
	.word b { font-weight: 800; }
</style>
