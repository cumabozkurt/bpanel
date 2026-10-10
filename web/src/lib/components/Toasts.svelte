<script>
	import { toasts } from '$lib/stores.js';
	import { t } from '$lib/i18n/index.js';
	import { CheckCircle2, AlertTriangle, X } from '@lucide/svelte';
	const dismiss = (id) => toasts.update((l) => l.filter((x) => x.id !== id));
</script>

<div class="toasts" role="status" aria-live="polite" aria-atomic="false">
	{#each $toasts as m (m.id)}
		<div class="toast card {m.kind}" role={m.kind === 'error' ? 'alert' : undefined}>
			{#if m.kind === 'error' || m.kind === 'warn'}<AlertTriangle size={16} aria-hidden="true" />{:else}<CheckCircle2 size={16} aria-hidden="true" />{/if}
			<span class="grow">{m.message}</span>
			<button class="x" onclick={() => dismiss(m.id)} aria-label={$t('common.dismiss')}><X size={14} /></button>
		</div>
	{/each}
</div>

<style>
	.toasts { position: fixed; right: 18px; bottom: 18px; display: flex; flex-direction: column; gap: 8px; z-index: 80; max-width: 420px; }
	.toast { display: flex; gap: 10px; align-items: flex-start; padding: 10px 10px 10px 14px; box-shadow: var(--shadow-lg); border-left: 4px solid var(--green); }
	.toast.ok :global(svg:first-child) { color: var(--green); flex: none; margin-top: 2px; }
	.toast.error { border-left-color: var(--red); }
	.toast.error :global(svg:first-child) { color: var(--red); flex: none; margin-top: 2px; }
	.toast.warn { border-left-color: var(--amber); }
	.toast.warn :global(svg:first-child) { color: var(--amber-text, var(--amber)); flex: none; margin-top: 2px; }
	.x { background: none; border: 0; color: var(--muted); cursor: pointer; padding: 2px; border-radius: 4px; display: inline-flex; }
	.x:hover { color: var(--text); background: var(--card-2); }
	@media (max-width: 600px) { .toasts { left: 10px; right: 10px; bottom: 10px; max-width: none; } }
</style>
