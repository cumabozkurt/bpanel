<script>
	import { ChevronLeft } from '@lucide/svelte';
	import ToolIcon from './ToolIcon.svelte';
	import { pageTitle } from '$lib/stores.js';
	// crumbs (G10): { label, items: [{ href?, text }] } — WHM-style "Home › Group › Tool"
	let { title, desc = '', icon = null, back = null, backLabel = '', actions, crumbs = null } = $props();
	// publish the heading for document.title (R2-UX-24); cleared when the page goes away
	$effect(() => {
		const v = title;
		pageTitle.set(v);
		return () => pageTitle.update((cur) => (cur === v ? '' : cur));
	});
</script>

<header class="ph">
	{#if crumbs?.items?.length}
		<nav class="crumbs small" aria-label={crumbs.label}>
			<ol>{#each crumbs.items as c}<li>{#if c.href}<a href={c.href}>{c.text}</a>{:else}<span>{c.text}</span>{/if}</li>{/each}<li aria-current="page">{title}</li></ol>
		</nav>
	{:else if back}<a class="back" href={back}><ChevronLeft size={14} /> {backLabel}</a>{/if}
	<div class="row head">
		{#if icon}<span class="ic"><ToolIcon {icon} size={38} /></span>{/if}
		<div class="grow">
			<h1>{title}</h1>
			{#if desc}<p class="muted">{desc}</p>{/if}
		</div>
		{#if actions}<div class="row acts">{@render actions()}</div>{/if}
	</div>
</header>

<style>
	.ph { margin-bottom: 20px; }
	.crumbs ol { list-style: none; display: flex; flex-wrap: wrap; gap: 4px; margin: 0 0 6px; padding: 0; color: var(--muted); }
	.crumbs li + li::before { content: '›'; margin-right: 4px; }
	.back { display: inline-flex; align-items: center; gap: 2px; font-size: 12.5px; margin-bottom: 6px; }
	h1 { margin-bottom: 2px; }
	p { margin: 0; max-width: 72ch; }
	.head { flex-wrap: wrap; align-items: flex-start; }
	.head > .grow { min-width: 200px; }
	.acts { flex-wrap: wrap; gap: 8px; }
	h1 { overflow-wrap: anywhere; }
	@media (max-width: 600px) {
		.ph { margin-bottom: 14px; }
		.ic { display: none; }
		.head > .grow { min-width: 0; flex-basis: 100%; }
		.acts { width: 100%; }
		.acts :global(.btn) { flex: 1 1 auto; }
	}
</style>
