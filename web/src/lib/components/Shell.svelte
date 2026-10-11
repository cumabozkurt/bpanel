<script>
	import {
		LayoutGrid, Globe, Mail, FolderOpen, Database, ShieldCheck, Archive, KeyRound, Search, Bell, Moon, Sun,
		ChevronDown, ChevronRight, LogOut, UserCog, Menu, Command, Home, ChevronsDownUp, ChevronsUpDown, ArrowLeftCircle,
		User, X, CheckCircle2, XCircle, Languages
	} from '@lucide/svelte';
	import Logo from './Logo.svelte';
	import LangSwitch from './LangSwitch.svelte';
	import ToolIcon from './ToolIcon.svelte';
	import { t, fmt, languages, locale, setLocale } from '$lib/i18n/index.js';
	import { session, meta, paletteOpen, logout, applyTheme } from '$lib/stores.js';
	import { allTools, visibleGroups, hasFeature } from '$lib/tools.js';
	import { openTool } from '$lib/actions.js';
	import { api } from '$lib/api.js';
	import { norm, toolHaystack, matches, score } from '$lib/search.js';
	import { auditLabel } from '$lib/util.js';
	import { trapFocus } from '$lib/a11y.js';
	import { goto } from '$app/navigation';
	import { page } from '$app/state';

	let { realm, sys = null, children } = $props();

	let q = $state('');
	let searchEl = $state();
	let showResults = $state(false);
	let activeIdx = $state(0);
	let userMenu = $state(false);
	let mobileNav = $state(false);
	let sideQ = $state('');
	let entities = $state(null); // accounts (admin) or domains (user) for the top-bar search
	let theme = $state(typeof document !== 'undefined' ? document.documentElement.dataset.theme || 'light' : 'light');
	let openCats = $state(JSON.parse((typeof localStorage !== 'undefined' && localStorage.getItem('bp_admin_cats')) || '["account_functions","account_info"]'));

	// notifications (recent audit events; hidden where the API offers none)
	let notifOpen = $state(false);
	let notif = $state(null); // null = not loaded, [] = loaded
	let notifAvailable = $state(false);
	let seenId = $state(Number((typeof localStorage !== 'undefined' && localStorage.getItem('bp_notif_seen')) || 0));
	let unread = $derived((notif ?? []).filter((n) => n.id > seenId).length);

	const userNav = [
		{ to: '/', icon: LayoutGrid, key: 'nav.tools', match: ['/'] },
		{ to: '/domains', icon: Globe, key: 'nav.domains', match: ['/domains', '/dns'] },
		{ to: '/email/accounts', icon: Mail, key: 'nav.email', match: ['/email'] },
		{ to: '/files', icon: FolderOpen, key: 'nav.files', match: ['/files', '/disk', '/ftp'] },
		{ to: '/databases', icon: Database, key: 'nav.databases', match: ['/databases'] },
		{ to: '/ssl', icon: ShieldCheck, key: 'nav.ssl', match: ['/ssl'] },
		{ to: '/backups', icon: Archive, key: 'nav.backups', match: ['/backups'] },
		{ to: '/security', icon: KeyRound, key: 'nav.security', match: ['/security'] }
	];

	let me = $derived($session?.user);
	let groups = $derived(visibleGroups('admin', me?.role, $session?.features));
	// R2-SYS-16: the Email entry is hidden when the install profile has no mail
	let userNavShown = $derived(userNav.filter((n) => n.to !== '/email/accounts' || hasFeature($session?.features, 'mail')));
	let cur = $derived(page.url.pathname);
	let curSearch = $derived(page.url.search.replace(/^\?/, ''));

	// Exactly one highlighted entry: the longest matching prefix (user) / first exact match (admin).
	let activeUserNav = $derived.by(() => {
		let best = null, len = -1;
		for (const n of userNav) for (const m of n.match) {
			const hit = m === '/' ? cur === '/' : cur === m || cur.startsWith(m + '/');
			if (hit && m.length > len) { best = n.to; len = m.length; }
		}
		return best;
	});
	let activeToolId = $derived.by(() => {
		const all = groups.flatMap((g) => g.tools).filter((x) => x.to);
		const exact = all.find((x) => { const [p, qq = ''] = x.to.split('?'); return p === cur && qq === curSearch; });
		if (exact) return exact.id;
		return all.find((x) => x.to.split('?')[0] === cur)?.id ?? null;
	});

	function visibleTools() {
		return allTools(realm, me?.role, $session?.features);
	}
	// R2-UX-31: the palette shortcut is Ctrl K everywhere except on macOS (⌘ K).
	const isMac = typeof navigator !== 'undefined' && /mac/i.test(navigator.userAgentData?.platform || navigator.platform || '');
	let badge = $derived(unread > 9 ? '9+' : String(unread));
	const printedAt = new Date();
	let results = $derived.by(() => {
		const query = q.trim();
		if (!query) return [];
		const tools = visibleTools()
			.filter((x) => matches(toolHaystack(x), query))
			.map((x) => ({ kind: 'tool', tool: x, label: $t('tools.' + x.id), sub: $t('groups.' + x.group), icon: x.icon }));
		const ents = (entities ?? [])
			.filter((e) => matches(e.hay, query))
			.map((e) => ({ kind: 'entity', to: e.to, label: e.label, sub: e.sub, icon: e.icon }));
		return [...tools, ...ents].sort((a, b) => score(a.label, query) - score(b.label, query)).slice(0, 10);
	});
	$effect(() => { results; activeIdx = 0; });

	async function loadEntities() {
		if (entities) return;
		entities = [];
		try {
			if (realm === 'admin') {
				const list = await api.get('/admin/accounts');
				entities = list.map((a) => ({ to: '/accounts?q=' + encodeURIComponent(a.username), label: a.username, sub: a.primary_domain + ' · ' + $t('shell.account'), hay: [a.username, a.primary_domain, a.email].join(' '), icon: User }));
			} else {
				const list = await api.get('/user/domains');
				entities = list.map((d) => ({ to: d.kind === 'sub' ? '/domains' : '/dns/' + d.name, label: d.name, sub: $t('domains.kind_' + d.kind), hay: d.name, icon: Globe }));
			}
		} catch { /* search still works for tools */ }
	}

	let sideGroups = $derived.by(() => {
		const query = sideQ.trim();
		if (!query) return groups;
		return groups
			.map((g) => ({ ...g, tools: g.tools.filter((x) => matches(toolHaystack({ ...x, group: g.id }), query)) }))
			.filter((g) => g.tools.length);
	});

	function toggleCat(id) {
		openCats = openCats.includes(id) ? openCats.filter((x) => x !== id) : [...openCats, id];
		localStorage.setItem('bp_admin_cats', JSON.stringify(openCats));
	}
	function expandAll(v) {
		openCats = v ? groups.map((g) => g.id) : [];
		localStorage.setItem('bp_admin_cats', JSON.stringify(openCats));
	}
	async function toggleTheme() {
		theme = theme === 'dark' ? 'light' : 'dark';
		applyTheme(theme);
		try { await api.put('/account/preferences', { theme }); } catch {}
	}
	async function changeLang(code) {
		setLocale(code);
		try { await api.put('/account/preferences', { lang: code }); } catch {}
	}
	async function doLogout() {
		await logout();
		goto('/login');
	}
	function closeAll() { userMenu = false; notifOpen = false; }
	function onKey(e) {
		const tag = (e.target?.tagName || '').toLowerCase();
		const typing = tag === 'input' || tag === 'textarea' || tag === 'select' || e.target?.isContentEditable;
		if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); $paletteOpen = !$paletteOpen; }
		else if ((e.ctrlKey || e.metaKey) && e.key === '/') { e.preventDefault(); (document.getElementById('side-search') || searchEl)?.focus(); }
		else if (e.key === '/' && !typing && !document.querySelector('[role=dialog]')) { e.preventDefault(); if (searchEl?.offsetParent) searchEl.focus(); else $paletteOpen = true; }
		else if (e.key === 'Escape') {
			if (mobileNav) { mobileNav = false; document.querySelector('.burger')?.focus(); }
			if (userMenu || notifOpen) { closeAll(); }
		}
	}
	function pick(r) {
		q = ''; showResults = false; searchEl?.blur();
		if (r.kind === 'tool') openTool(r.tool); else goto(r.to);
	}
	function searchKey(e) {
		if (e.key === 'ArrowDown') { e.preventDefault(); showResults = true; activeIdx = Math.min(activeIdx + 1, results.length - 1); }
		else if (e.key === 'ArrowUp') { e.preventDefault(); activeIdx = Math.max(activeIdx - 1, 0); }
		else if (e.key === 'Enter' && results[activeIdx]) { e.preventDefault(); pick(results[activeIdx]); }
		else if (e.key === 'Escape') { e.stopPropagation(); if (q) q = ''; else searchEl.blur(); }
	}

	// notifications
	// Admins read the full audit log; resellers and hosting users read their own
	// activity feed (GET /account/activity, which also lists failed logins against them).
	let fullAudit = $derived(realm === 'admin' && me?.role === 'admin');
	async function loadNotif() {
		try {
			if (fullAudit) notif = await api.get('/admin/audit?limit=10', { noRedirect: true });
			else notif = (await api.get('/account/activity?limit=10', { noRedirect: true })).items;
			notifAvailable = true;
		} catch { notifAvailable = false; notif = null; }
	}
	$effect(() => { if (me) loadNotif(); });
	function toggleNotif(e) {
		e.stopPropagation();
		userMenu = false;
		notifOpen = !notifOpen;
		if (notifOpen) {
			loadNotif().then(() => {
				const max = Math.max(seenId, ...(notif ?? []).map((n) => n.id));
				seenId = max;
				localStorage.setItem('bp_notif_seen', String(max));
			});
		}
	}
	function menuKey(e) {
		const items = [...e.currentTarget.querySelectorAll('[role=menuitem]')];
		const i = items.indexOf(document.activeElement);
		if (e.key === 'ArrowDown') { e.preventDefault(); items[(i + 1) % items.length]?.focus(); }
		else if (e.key === 'ArrowUp') { e.preventDefault(); items[(i - 1 + items.length) % items.length]?.focus(); }
		else if (e.key === 'Escape') { e.preventDefault(); userMenu = false; document.getElementById('um-btn')?.focus(); }
	}
	function focusFirstItem(node) { setTimeout(() => node.querySelector('[role=menuitem]')?.focus(), 0); }

	$effect(() => {
		// lock page scroll while the mobile drawer is open
		document.body.style.overflow = mobileNav ? 'hidden' : '';
		return () => (document.body.style.overflow = '');
	});
	$effect(() => { cur; mobileNav = false; });
</script>

<svelte:window onkeydown={onKey} onclick={closeAll} />

<a class="skip" href="#main-content">{$t('shell.skip_to_content')}</a>
<div class="shell" class:admin={realm === 'admin'}>
	{#if mobileNav}<div class="drawer-backdrop" role="presentation" onclick={() => (mobileNav = false)}></div>{/if}
	<aside class:open={mobileNav} id="side-nav" aria-label={$t('shell.navigation')}>
		<div class="brand-row">
			<a class="brand" href="/"><Logo size={30} /><span class="sr-only"> — {$t('nav.home')}</span></a>
			<button class="btn ghost sm close-nav" aria-label={$t('common.close')} onclick={() => (mobileNav = false)}><X size={18} /></button>
		</div>
		{#if realm === 'admin'}
			<div class="side-search">
				<Search size={14} aria-hidden="true" />
				<input id="side-search" type="search" bind:value={sideQ} placeholder={$t('shell.search_menu')} aria-label={$t('shell.search_menu')} />
			</div>
			<div class="exp">
				<button onclick={() => expandAll(true)}><ChevronsUpDown size={13} /> {$t('shell.expand')}</button>
				<button onclick={() => expandAll(false)}><ChevronsDownUp size={13} /> {$t('shell.collapse')}</button>
			</div>
			<nav class="cats" aria-label={$t('shell.navigation')}>
				<a href="/" class="home" class:active={cur === '/'} aria-current={cur === '/' ? 'page' : undefined}><Home size={15} /> {$t('nav.home')}</a>
				{#each sideGroups as g}
					{@const open = openCats.includes(g.id) || sideQ.trim() !== ''}
					<div class="cat">
						<button class="cat-h" aria-expanded={open} onclick={() => toggleCat(g.id)}>
							{#if open}<ChevronDown size={14} />{:else}<ChevronRight size={14} />{/if}
							<span>{$t('groups.' + g.id)}</span>
						</button>
						{#if open}
							<ul>
								{#each g.tools as tool}
									<li>
										<button class="cat-l" class:active={tool.id === activeToolId} aria-current={tool.id === activeToolId ? 'page' : undefined} onclick={() => { mobileNav = false; openTool(tool); }}>
											{$t('tools.' + tool.id)}
										</button>
									</li>
								{/each}
							</ul>
						{/if}
					</div>
				{:else}
					<p class="side-empty">{$t('palette.no_results')}</p>
				{/each}
			</nav>
		{:else}
			<nav class="main-nav" aria-label={$t('shell.navigation')}>
				{#each userNavShown as n}
					<a href={n.to} class:active={activeUserNav === n.to} aria-current={activeUserNav === n.to ? 'page' : undefined}>
						<n.icon size={18} strokeWidth={1.7} aria-hidden="true" /> <span>{$t(n.key)}</span>
					</a>
				{/each}
			</nav>
		{/if}
		<div class="side-foot">BOZKURT PANEL {$meta?.version ?? ''}</div>
	</aside>

	<div class="main">
		{#if realm === 'admin'}
			<div class="metastrip" role="region" aria-label={$t('shell.server_strip')}>
				<span><em>{$t('shell.username')}</em> {me?.username}</span>
				<span class="ellip"><em>{$t('shell.hostname')}</em> {sys?.hostname || $meta?.hostname || '—'}</span>
				{#if sys?.os}<span class="hide-sm"><em>{$t('shell.os')}</em> {sys.os}</span>{/if}
				<span class="hide-sm"><em>{$t('shell.version')}</em> {$meta?.version}</span>
				{#if sys?.load}<span class="push hide-sm"><em>{$t('shell.load')}</em> {sys.load.map((x) => x.toFixed(2)).join(' ')}</span>{/if}
			</div>
		{/if}
		{#if $session?.impersonator}
			<div class="imp">
				<ArrowLeftCircle size={15} />
				<span class="grow">{$t('shell.impersonating', { admin: $session.impersonator, user: me?.username })}</span>
				<button class="linkbtn" onclick={doLogout}>{$t('shell.end_impersonation')}</button>
			</div>
		{/if}
		<header class="topbar">
			<button class="btn ghost sm burger" aria-label={$t('shell.menu')} aria-controls="side-nav" aria-expanded={mobileNav} onclick={(e) => { e.stopPropagation(); mobileNav = !mobileNav; }}><Menu size={18} /></button>
			<a class="mlogo" href="/" aria-label={$t('nav.home')}><Logo size={26} word={false} /></a>
			<div class="search">
				<Search size={16} aria-hidden="true" />
				<input bind:this={searchEl} type="search" bind:value={q}
					onfocus={() => { showResults = true; loadEntities(); }} onblur={() => setTimeout(() => (showResults = false), 150)}
					oninput={() => (showResults = true)} onkeydown={searchKey}
					role="combobox" aria-expanded={showResults && !!q.trim()} aria-haspopup="listbox" aria-autocomplete="list" aria-controls="search-results" aria-activedescendant={showResults && results[activeIdx] ? 'sr-' + activeIdx : undefined}
					placeholder={realm === 'admin' ? $t('shell.search_admin') : $t('shell.search_tools')} aria-label={realm === 'admin' ? $t('shell.search_admin') : $t('shell.search_tools')} />
				{#if showResults && q.trim()}
					<ul class="results card" id="search-results" role="listbox" aria-label={$t('shell.search_results')}>
						{#each results as r, i}
							<li id={'sr-' + i} role="option" aria-selected={i === activeIdx}>
								<button tabindex="-1" class:sel={i === activeIdx} onmousedown={(e) => { e.preventDefault(); pick(r); }} onmouseenter={() => (activeIdx = i)}>
									<ToolIcon icon={r.icon} size={20} /> <span class="grow">{r.label}</span> <span class="muted small">{r.sub}</span>
								</button>
							</li>
						{:else}
							<li class="noresult muted small" role="option" aria-selected="false" aria-disabled="true">{$t('palette.no_results')}</li>
						{/each}
					</ul>
				{/if}
			</div>
			<button class="btn ghost sm msearch" onclick={() => ($paletteOpen = true)} aria-label={$t('common.search')}><Search size={18} /></button>
			<button class="btn ghost sm kbd" onclick={() => ($paletteOpen = true)} title={$t('palette.title')}>{#if isMac}<Command size={14} aria-hidden="true" /><span class="sr-only">⌘</span>{:else}Ctrl{/if} K<span class="sr-only"> — {$t('palette.title')}</span></button>
			<div class="spacer"></div>
			<span class="hide-xs"><LangSwitch compact /></span>
			<button class="btn ghost sm hide-xs" onclick={toggleTheme} aria-label={$t('prefs.theme_toggle')} title={$t('prefs.theme_toggle')}>
				{#if theme === 'dark'}<Sun size={17} />{:else}<Moon size={17} />{/if}
			</button>
			{#if notifAvailable}
				<div class="um">
					<button class="btn ghost sm bell" onclick={toggleNotif} aria-haspopup="dialog" aria-expanded={notifOpen} title={$t('shell.notifications')}>
						<Bell size={17} aria-hidden="true" /><span class="sr-only">{unread ? $t('shell.notifications_unread', { n: unread }) : $t('shell.notifications')}</span>{#if unread}<span class="dotn" aria-hidden="true">{badge}</span>{/if}
					</button>
					{#if notifOpen}
						<!-- svelte-ignore a11y_click_events_have_key_events -->
						<div class="menu notif card" role="dialog" aria-label={$t('shell.notifications')} tabindex="-1" onclick={(e) => e.stopPropagation()} use:trapFocus={{ onEscape: () => { notifOpen = false; document.querySelector('.bell')?.focus(); } }}>
							<div class="nh"><b class="grow">{$t('shell.recent_activity')}</b>{#if fullAudit}<a href="/audit" onclick={() => (notifOpen = false)}>{$t('shell.view_all')}</a>{/if}</div>
							<ul>
								{#each notif ?? [] as n}
									<li>
										{#if n.ok}<CheckCircle2 size={15} class="okc" />{:else}<XCircle size={15} class="badc" />{/if}
										<div class="grow"><div>{auditLabel(n.action)}{#if n.target && n.target !== n.actor} <span class="muted">{n.target}</span>{/if}</div>
											<div class="muted small">{n.actor || '—'} · {$fmt.date(n.at)}</div></div>
									</li>
								{:else}
									<li class="muted">{$t('shell.no_activity')}</li>
								{/each}
							</ul>
						</div>
					{/if}
				</div>
			{/if}
			<div class="um">
				<button id="um-btn" class="btn ghost sm user" onclick={(e) => { e.stopPropagation(); notifOpen = false; userMenu = !userMenu; }} aria-haspopup="menu" aria-expanded={userMenu}>
					<span class="avatar" aria-hidden="true">{me?.username?.[0]?.toUpperCase()}</span>
					<span class="hide-sm" aria-hidden="true">{me?.username}</span><span class="sr-only">{$t('shell.user_menu', { user: me?.username ?? '' })}</span>
					<ChevronDown size={14} aria-hidden="true" />
				</button>
				{#if userMenu}
					<div class="menu card" role="menu" tabindex="-1" onkeydown={menuKey} onclick={(e) => e.stopPropagation()} use:focusFirstItem>
						<a href="/preferences" role="menuitem" onclick={() => (userMenu = false)}><UserCog size={15} /> {$t('nav.preferences')}</a>
						<a href="/security" role="menuitem" onclick={() => (userMenu = false)}><KeyRound size={15} /> {$t('nav.security')}</a>
						<button role="menuitem" class="show-xs" onclick={() => { toggleTheme(); userMenu = false; }}>{#if theme === 'dark'}<Sun size={15} />{:else}<Moon size={15} />{/if} {$t('prefs.theme_toggle')}</button>
						{#each languages.filter((l) => l.code !== $locale) as l}
							<button role="menuitem" class="show-xs" onclick={() => { changeLang(l.code); userMenu = false; }}><Languages size={15} /> {l.name}</button>
						{/each}
						<button role="menuitem" onclick={doLogout}><LogOut size={15} /> {$t('shell.logout')}</button>
					</div>
				{/if}
			</div>
		</header>
		<main class="content" id="main-content" tabindex="-1">
			<div class="printhead" aria-hidden="true">BOZKURT PANEL · {sys?.hostname || $meta?.hostname || ''} · {me?.username} · {$fmt.date(Math.floor(printedAt.getTime() / 1000))}</div>
			{@render children()}
		</main>
	</div>
</div>

<style>
	.skip { position: absolute; left: 8px; top: -60px; z-index: 100; background: var(--primary); color: #fff; padding: 8px 14px; border-radius: var(--radius); font-weight: 600; }
	.skip:focus { top: 8px; text-decoration: none; color: #fff; }
	.shell { display: grid; grid-template-columns: 216px 1fr; min-height: 100vh; background: linear-gradient(to right, var(--sidebar) 216px, transparent 216px); }
	.shell.admin { grid-template-columns: 248px 1fr; background: linear-gradient(to right, var(--sidebar) 248px, transparent 248px); }
	aside { background: var(--sidebar); color: var(--sidebar-text); display: flex; flex-direction: column; position: sticky; top: 0; height: 100vh; overflow-y: auto; z-index: 30; }
	.brand-row { display: flex; align-items: center; justify-content: space-between; }
	.brand { display: block; padding: 16px 16px 18px; }
	.brand:hover { text-decoration: none; }
	.close-nav { display: none; color: var(--sidebar-text); margin-right: 8px; }
	.main-nav { display: flex; flex-direction: column; padding: 0 8px; gap: 2px; }
	.main-nav a { display: flex; align-items: center; gap: 12px; padding: 9px 12px; color: var(--sidebar-text); border-radius: 6px; font-size: 14px; }
	.main-nav a:hover { background: var(--sidebar-2); color: #fff; text-decoration: none; }
	.main-nav a.active { background: var(--sidebar-active); color: #fff; box-shadow: inset 3px 0 0 var(--accent); }
	aside a:focus-visible, aside button:focus-visible, aside input:focus-visible { outline: 2px solid var(--accent); outline-offset: -2px; }
	.side-foot { margin-top: auto; padding: 14px 16px; font-size: 11px; color: var(--sidebar-foot); letter-spacing: 0.04em; }
	.side-empty { padding: 8px 12px; font-size: 12.5px; color: var(--sidebar-foot); }
	.side-search { margin: 0 12px 8px; display: flex; align-items: center; gap: 6px; background: var(--sidebar-2); border-radius: 6px; padding: 0 8px; color: var(--sidebar-text); }
	.side-search input { background: transparent; border: 0; color: #fff; min-height: 32px; padding: 4px 0; }
	.side-search input::placeholder { color: var(--sidebar-foot); }
	.exp { display: flex; gap: 6px; margin: 0 12px 10px; }
	.exp button { flex: 1; display: inline-flex; align-items: center; justify-content: center; gap: 4px; background: transparent; border: 1px solid var(--sidebar-2); color: var(--sidebar-text); border-radius: 5px; font: inherit; font-size: 11.5px; padding: 4px; cursor: pointer; }
	.exp button:hover { background: var(--sidebar-2); }
	.cats { padding: 0 6px 12px; }
	.home { display: flex; align-items: center; gap: 8px; padding: 7px 10px; color: var(--sidebar-text); border-radius: 5px; }
	.home:hover, .home.active { background: var(--sidebar-active); color: #fff; text-decoration: none; }
	.cat-h { display: flex; align-items: center; gap: 6px; width: 100%; padding: 7px 8px; background: none; border: 0; color: var(--sidebar-text); font: inherit; font-size: 13px; text-align: left; cursor: pointer; border-radius: 5px; }
	.cat-h:hover { background: var(--sidebar-2); color: #fff; }
	.cat ul { list-style: none; margin: 0 0 4px; padding: 0 0 0 26px; }
	.cat-l { display: flex; align-items: center; gap: 6px; width: 100%; background: none; border: 0; color: var(--sidebar-text); font: inherit; font-size: 12.5px; padding: 4px 8px; text-align: left; cursor: pointer; border-radius: 4px; }
	.cat-l:hover { color: #fff; background: var(--sidebar-2); }
	.cat-l.active { color: #fff; background: var(--sidebar-active); box-shadow: inset 2px 0 0 var(--accent); }
	.main { min-width: 0; display: flex; flex-direction: column; }
	.metastrip { display: flex; flex-wrap: wrap; gap: 4px 22px; padding: 6px 24px; font-size: 12px; background: var(--card-2); border-bottom: 1px solid var(--border); color: var(--text); }
	.metastrip em { font-style: normal; color: var(--muted); margin-right: 4px; }
	.metastrip .push { margin-left: auto; }
	.imp { display: flex; align-items: center; gap: 8px; padding: 7px 24px; background: var(--amber-soft); color: var(--text); border-bottom: 1px solid var(--border); font-size: 13px; flex-wrap: wrap; }
	.topbar { display: flex; align-items: center; gap: 8px; height: 56px; padding: 0 20px; background: var(--card); border-bottom: 1px solid var(--border); box-shadow: var(--shadow); position: sticky; top: 0; z-index: 20; }
	.burger, .mlogo, .msearch, .show-xs { display: none !important; }
	.search { position: relative; display: flex; align-items: center; gap: 8px; flex: 0 1 420px; min-width: 0; border: 1px solid var(--border-strong); border-radius: var(--radius); padding: 0 10px; color: var(--muted); background: var(--card); }
	.search input { border: 0; padding: 6px 0; min-height: 34px; background: transparent; min-width: 0; }
	.search input:focus { outline: none; }
	.search:focus-within { border-color: var(--primary); box-shadow: 0 0 0 2px color-mix(in srgb, var(--primary) 25%, transparent); }
	.results { position: absolute; top: calc(100% + 6px); left: 0; right: 0; list-style: none; margin: 0; padding: 6px; box-shadow: var(--shadow-lg); z-index: 40; max-height: 70vh; overflow: auto; }
	.results button { display: flex; align-items: center; gap: 10px; width: 100%; padding: 7px 8px; background: none; border: 0; color: var(--text); font: inherit; border-radius: 5px; cursor: pointer; text-align: left; }
	.results button.sel { background: var(--blue-soft); }
	.noresult { padding: 8px; }
	.kbd { color: var(--muted); border: 1px solid var(--border); }
	.spacer { flex: 1; }
	.um { position: relative; }
	.user { gap: 8px; }
	.bell { position: relative; }
	.dotn { position: absolute; top: 0; right: 0; min-width: 16px; height: 16px; padding: 0 4px; border-radius: 8px; background: var(--red-strong); color: #fff; font-size: 10px; font-weight: 700; line-height: 16px; text-align: center; }
	.avatar { width: 26px; height: 26px; border-radius: 50%; background: var(--accent); color: #062c28; display: grid; place-items: center; font-weight: 700; font-size: 12px; }
	.menu { position: absolute; right: 0; top: calc(100% + 6px); min-width: 210px; padding: 6px; box-shadow: var(--shadow-lg); z-index: 40; display: flex; flex-direction: column; }
	.menu a, .menu button { display: flex; align-items: center; gap: 10px; padding: 8px 10px; color: var(--text); background: none; border: 0; font: inherit; text-align: left; cursor: pointer; border-radius: 5px; }
	.menu a:hover, .menu button:hover, .menu a:focus-visible, .menu button:focus-visible { background: var(--card-2); text-decoration: none; outline: none; box-shadow: inset 0 0 0 2px var(--primary); }
	.notif { width: min(380px, calc(100vw - 24px)); padding: 0; }
	.notif .nh { display: flex; align-items: center; padding: 10px 14px; border-bottom: 1px solid var(--border); }
	.notif .nh a { display: inline; padding: 0; }
	.notif ul { list-style: none; margin: 0; padding: 4px 0; max-height: 60vh; overflow: auto; }
	.notif li { display: flex; gap: 10px; padding: 8px 14px; font-size: 13px; align-items: flex-start; }
	.notif li + li { border-top: 1px solid var(--border); }
	.notif :global(.okc) { color: var(--green); flex: none; margin-top: 2px; }
	.notif :global(.badc) { color: var(--red); flex: none; margin-top: 2px; }
	.content { padding: 24px 28px 48px; max-width: 1480px; width: 100%; }
	.content:focus { outline: none; }
	.drawer-backdrop { display: none; }
	@media (max-width: 900px) {
		.shell, .shell.admin { grid-template-columns: 1fr; background: none; }
		aside { position: fixed; left: 0; top: 0; width: min(280px, 86vw); transform: translateX(-100%); transition: transform 0.2s; box-shadow: var(--shadow-lg); visibility: hidden; }
		aside.open { transform: none; visibility: visible; z-index: 70; }
		.drawer-backdrop { display: block; position: fixed; inset: 0; background: rgba(10, 15, 25, 0.5); z-index: 65; }
		.close-nav { display: inline-flex; }
		.burger { display: inline-flex !important; }
		.hide-sm { display: none; }
		.topbar { padding: 0 12px; gap: 4px; }
		.content { padding: 18px 14px 40px; }
		.kbd { display: none; }
		.metastrip { padding: 6px 14px; }
		.imp { padding: 7px 14px; }
	}
	@media (max-width: 600px) {
		.search { display: none; }
		.msearch, .mlogo { display: inline-flex !important; }
		.mlogo { align-items: center; }
		.hide-xs { display: none !important; }
		.show-xs { display: flex !important; }
		.ellip { max-width: 60vw; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
		.content { padding: 14px 10px 32px; }
	}
	@media (prefers-reduced-motion: reduce) { aside { transition: none; } }
	/* R2-UX-41: explicit transparent background so contrast tools resolve the top-bar colour */
	#um-btn { background: transparent; }
	/* R2-UX-28: Windows High Contrast — keep the active item visible */
	@media (forced-colors: active) {
		.main-nav a.active, .cat-l.active, .home.active { forced-color-adjust: none; background: Highlight; color: HighlightText; outline: 2px solid Highlight; outline-offset: -2px; }
		.cat-l { color: LinkText; }
		.dotn { forced-color-adjust: none; background: Highlight; color: HighlightText; }
	}
	@media print {
		aside, .topbar, .metastrip, .imp, .skip, .drawer-backdrop { display: none !important; }
		.shell, .shell.admin { display: block; background: none; }
		.content { padding: 0; max-width: none; }
	}
</style>
