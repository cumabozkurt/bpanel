<script>
	import { X } from '@lucide/svelte';
	import { t } from '$lib/i18n/index.js';
	import { trapFocus } from '$lib/a11y.js';
	// canClose(): return false to keep the dialog open (e.g. unsaved changes).
	let { open = $bindable(false), title = '', width = 520, children, footer, canClose = null, initial = null } = $props();
	const uid = 'dlg-' + Math.random().toString(36).slice(2, 8);
	export function close() {
		if (canClose && canClose() === false) return;
		open = false;
	}
</script>

{#if open}
	<div class="backdrop" role="presentation" onclick={(e) => e.target === e.currentTarget && close()}>
		<div class="modal card" role="dialog" aria-modal="true" aria-labelledby={uid} tabindex="-1" style="max-width:{width}px" use:trapFocus={{ initial, onEscape: close }}>
			<div class="card-head">
				<h2 class="grow" id={uid}>{title}</h2>
				<button type="button" class="btn ghost sm" aria-label={$t('common.close')} data-skip-autofocus onclick={close}><X size={16} /></button>
			</div>
			<div class="card-body">{@render children?.()}</div>
			{#if footer}<div class="foot">{@render footer()}</div>{/if}
		</div>
	</div>
{/if}

<style>
	.backdrop { position: fixed; inset: 0; background: rgba(10, 15, 25, 0.5); display: grid; place-items: start center; padding: 8vh 16px; z-index: 50; overflow: auto; }
	.modal { width: 100%; box-shadow: var(--shadow-lg); }
	.modal:focus { outline: none; }
	.foot { display: flex; justify-content: flex-end; gap: 8px; padding: 12px 16px; border-top: 1px solid var(--border); background: var(--card-2); border-radius: 0 0 var(--radius) var(--radius); flex-wrap: wrap; }
	@media (max-width: 600px) { .backdrop { padding: 12px 8px; } }
</style>
