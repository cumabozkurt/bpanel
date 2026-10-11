<script>
	import { Search, CornerDownLeft, User, Globe, Zap } from '@lucide/svelte';
	import { paletteOpen, session } from '$lib/stores.js';
	import { allTools } from '$lib/tools.js';
	import { t } from '$lib/i18n/index.js';
	import { openTool } from '$lib/actions.js';
	import { api } from '$lib/api.js';
	import { norm, toolHaystack, matches, score } from '$lib/search.js';
	import { trapFocus } from '$lib/a11y.js';
	import { goto } from '$app/navigation';
	import ToolIcon from './ToolIcon.svelte';

	let { realm } = $props();
	let q = $state('');
	let sel = $state(0);
	let input = $state();
	let listEl = $state();
	let accounts = $state([]);
	let domains = $state([]);

	const quick = $derived(
		realm === 'admin'
			? [{ id: 'qa_create_account', to: '/accounts/new' }, { id: 'qa_add_package', to: '/packages?new=1' }, ...($session?.user?.role === 'admin' ? [{ id: 'qa_restart_services', to: '/services' }] : [])]
			: [...($session?.features?.mail === false ? [] : [{ id: 'qa_new_email', to: '/email/accounts?new=1' }]), { id: 'qa_new_db', to: '/databases?new=1' }, { id: 'qa_new_domain', to: '/domains?new=1' }, { id: 'qa_autossl', to: '/ssl' }, { id: 'qa_backup_now', to: '/backups' }]
	);

	$effect(() => {
		if ($paletteOpen) {
			q = '';
			sel = 0;
			if (realm === 'admin') api.get('/admin/accounts').then((a) => (accounts = a)).catch(() => {});
			else api.get('/user/domains').then((d) => (domains = d)).catch(() => {});
		}
	});

	let items = $derived.by(() => {
		const query = q.trim();
		const tools = allTools(realm, $session?.user?.role, $session?.features)
			.map((x) => ({ kind: 'tool', tool: x, label: $t('tools.' + x.id), sub: $t('groups.' + x.group), icon: x.icon, hay: toolHaystack(x) }));
		const acts = quick.map((x) => ({ kind: 'action', to: x.to, label: $t('palette.' + x.id), sub: $t('palette.action'), icon: Zap, hay: norm($t('palette.' + x.id)) }));
		const accs = accounts.map((a) => ({ kind: 'account', to: '/accounts?q=' + encodeURIComponent(a.username), label: a.username, sub: a.primary_domain, icon: User, hay: [a.username, a.primary_domain, a.email].join(' ') }));
		const doms = domains.map((d) => ({ kind: 'domain', to: d.kind === 'sub' || $session?.features?.dns === false ? '/domains' : '/dns/' + d.name, label: d.name, sub: $t('domains.kind_' + d.kind), icon: Globe, hay: d.name }));
		if (!query) return [...acts, ...tools.slice(0, 9)];
		return [...acts, ...tools, ...accs, ...doms]
			.filter((x) => matches(x.hay + ' ' + x.label + ' ' + x.sub, query))
			.sort((a, b) => score(a.label, query) - score(b.label, query))
			.slice(0, 14);
	});

	function go(it) {
		$paletteOpen = false;
		if (it.kind === 'tool') openTool(it.tool);
		else goto(it.to);
	}
	function move(n) {
		sel = Math.max(0, Math.min(items.length - 1, n));
		setTimeout(() => listEl?.querySelector('#pal-' + sel)?.scrollIntoView({ block: 'nearest' }), 0);
	}
	function key(e) {
		if (e.key === 'ArrowDown') { move(sel + 1); e.preventDefault(); }
		else if (e.key === 'ArrowUp') { move(sel - 1); e.preventDefault(); }
		else if (e.key === 'Home' && e.ctrlKey) { move(0); e.preventDefault(); }
		else if (e.key === 'End' && e.ctrlKey) { move(items.length - 1); e.preventDefault(); }
		else if (e.key === 'Enter' && items[sel]) { go(items[sel]); e.preventDefault(); }
		else if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); $paletteOpen = false; }
	}
</script>

{#if $paletteOpen}
	<div class="backdrop" role="presentation" onclick={(e) => e.target === e.currentTarget && ($paletteOpen = false)}>
		<div class="pal card" role="dialog" tabindex="-1" aria-modal="true" aria-label={$t('palette.title')} use:trapFocus={{ initial: 'input', onEscape: () => ($paletteOpen = false) }}>
			<div class="inp">
				<Search size={18} aria-hidden="true" />
				<input bind:this={input} bind:value={q} oninput={() => (sel = 0)} onkeydown={key} placeholder={$t('palette.placeholder')} aria-label={$t('palette.placeholder')}
					role="combobox" aria-expanded="true" aria-controls="pal-list" aria-autocomplete="list" aria-activedescendant={items[sel] ? 'pal-' + sel : undefined} />
				<kbd>Esc</kbd>
			</div>
			<ul id="pal-list" tabindex="-1" role="listbox" aria-label={$t('palette.title')} bind:this={listEl}>
				{#each items as it, i}
					<li id={'pal-' + i} role="option" aria-selected={i === sel}>
						<button tabindex="-1" class:sel={i === sel} onmouseenter={() => (sel = i)} onclick={() => go(it)}>
							<ToolIcon icon={it.icon} size={22} />
							<span class="grow">{it.label}</span>
							<span class="muted small sub">{it.sub}</span>
							{#if i === sel}<CornerDownLeft size={14} aria-hidden="true" />{/if}
						</button>
					</li>
				{:else}
					<li class="empty" role="option" aria-selected="false" aria-disabled="true">{$t('palette.no_results')}</li>
				{/each}
			</ul>
			<div class="hint muted small">{$t('palette.hint')}</div>
		</div>
	</div>
{/if}

<style>
	.backdrop { position: fixed; inset: 0; background: rgba(10, 15, 25, 0.45); z-index: 60; display: grid; place-items: start center; padding: 12vh 16px; }
	.pal { width: 100%; max-width: 620px; box-shadow: var(--shadow-lg); overflow: hidden; }
	.inp { display: flex; align-items: center; gap: 10px; padding: 12px 16px; border-bottom: 1px solid var(--border); color: var(--muted); }
	.inp input { border: 0; padding: 4px 0; font-size: 16px; outline: none; background: transparent; }
	.inp input:focus { outline: none; }
	kbd { font-size: 11px; border: 1px solid var(--border); border-radius: 4px; padding: 1px 5px; color: var(--muted); }
	ul { list-style: none; margin: 0; padding: 6px; max-height: 50vh; overflow: auto; }
	li button { display: flex; align-items: center; gap: 12px; width: 100%; padding: 8px 10px; border: 0; background: none; border-radius: 6px; color: var(--text); font: inherit; text-align: left; cursor: pointer; }
	li button.sel { background: var(--blue-soft); }
	.hint { padding: 8px 16px; border-top: 1px solid var(--border); background: var(--card-2); }
	@media (max-width: 600px) {
		.backdrop { padding: 8px; }
		.sub { display: none; }
		.hint { display: none; }
	}
</style>
