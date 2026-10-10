<script>
	// "Coming soon" state for roadmap tools (R2-UX-33): no version numbers, a clear status,
	// and a way back to the tools that work today.
	import { Hourglass, ArrowLeft } from '@lucide/svelte';
	import { t } from '$lib/i18n/index.js';
	import { session } from '$lib/stores.js';
	import { allTools } from '$lib/tools.js';
	import PageHead from '$lib/components/PageHead.svelte';
	let { params, realm } = $props();
	let tool = $derived(allTools(realm, $session?.user?.role, $session?.features).find((x) => x.id === params.id));
</script>

<PageHead title={$t('tools.' + params.id)} icon={tool?.icon ?? Hourglass} back="/" backLabel={$t('nav.home')} />
<section class="card card-body soonpage" aria-labelledby="soon-h">
	<span class="badge amber"><Hourglass size={12} aria-hidden="true" /> {$t('common.soon')}</span>
	<h2 id="soon-h">{$t('soon.title')}</h2>
	<p>{$t('soon.body')}</p>
	<p class="muted small">{$t('soon.roadmap')}</p>
	<a class="btn" href="/"><ArrowLeft size={15} aria-hidden="true" /> {$t('soon.back_to_tools')}</a>
</section>

<style>
	.soonpage { max-width: 720px; display: flex; flex-direction: column; align-items: flex-start; gap: 8px; }
	.soonpage h2 { margin-top: 4px; }
	.soonpage p { margin: 0; }
</style>
