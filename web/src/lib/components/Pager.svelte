<script>
	import { ChevronLeft, ChevronRight } from '@lucide/svelte';
	import { t } from '$lib/i18n/index.js';
	let { tbl, sizes = [25, 50, 100] } = $props();
</script>

{#if tbl.total > sizes[0]}
	<nav class="pager" aria-label={$t('common.pagination')}>
		<span class="muted small">{$t('common.range', { from: tbl.from, to: tbl.to, total: tbl.total })}</span>
		<span class="grow"></span>
		<label class="small muted per">{$t('common.per_page')}
			<select value={tbl.size} onchange={(e) => tbl.setSize(Number(e.currentTarget.value))}>{#each sizes as s}<option value={s}>{s}</option>{/each}</select></label>
		<button type="button" class="btn sm" disabled={tbl.pageNo <= 1} onclick={() => tbl.go(tbl.pageNo - 1)} aria-label={$t('common.prev_page')}><ChevronLeft size={14} /></button>
		<span class="small" aria-live="polite">{$t('common.page_of', { n: Math.min(tbl.pageNo, tbl.pages), total: tbl.pages })}</span>
		<button type="button" class="btn sm" disabled={tbl.pageNo >= tbl.pages} onclick={() => tbl.go(tbl.pageNo + 1)} aria-label={$t('common.next_page')}><ChevronRight size={14} /></button>
	</nav>
{/if}

<style>
	.pager { display: flex; align-items: center; gap: 8px; padding: 10px 14px; border-top: 1px solid var(--border); flex-wrap: wrap; }
	.per { display: inline-flex; align-items: center; gap: 6px; }
	.per select { width: auto; min-height: 28px; padding: 2px 6px; }
</style>
