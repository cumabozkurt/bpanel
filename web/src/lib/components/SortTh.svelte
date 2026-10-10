<script>
	import { ArrowUp, ArrowDown, ArrowUpDown } from '@lucide/svelte';
	import { t } from '$lib/i18n/index.js';
	let { tbl, key, label, cls = '', style = '' } = $props();
	let on = $derived(tbl.key === key);
</script>

<th class={cls} {style} aria-sort={on ? (tbl.dir > 0 ? 'ascending' : 'descending') : 'none'}>
	<button type="button" class="sortbtn" onclick={() => tbl.toggle(key)} title={$t('common.sort_by', { col: label })}>
		<span>{label}</span>
		{#if on}{#if tbl.dir > 0}<ArrowUp size={12} aria-hidden="true" />{:else}<ArrowDown size={12} aria-hidden="true" />{/if}{:else}<ArrowUpDown size={12} class="dim" aria-hidden="true" />{/if}
	</button>
</th>

<style>
	.sortbtn { display: inline-flex; align-items: center; gap: 4px; background: none; border: 0; padding: 0; font: inherit; color: inherit; text-transform: inherit; letter-spacing: inherit; cursor: pointer; }
	.sortbtn:hover { color: var(--text); }
	.sortbtn :global(.dim) { opacity: 0.45; }
	th[aria-sort='ascending'] .sortbtn, th[aria-sort='descending'] .sortbtn { color: var(--text); }
</style>
