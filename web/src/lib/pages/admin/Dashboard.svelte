<script>
	import { X, ChevronDown, ChevronRight, Star, Users, PauseCircle, Package, UserCog, ArrowRight, Pencil, Check, Plus, RotateCcw } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t, fmt } from '$lib/i18n/index.js';
	import { session, pageTitle } from '$lib/stores.js';
	import { visibleGroups } from '$lib/tools.js';
	import { openTool } from '$lib/actions.js';
	import ToolIcon from '$lib/components/ToolIcon.svelte';

	let sum = $state(null);
	let hideSteps = $state(localStorage.getItem('bp_hide_steps') === '1');
	let open = $state([]);
	api.get('/admin/summary').then((s) => (sum = s)).catch(() => {});
	$effect(() => { pageTitle.set($t('adash.title')); return () => pageTitle.set(''); });
	// R2-UX-03: a reseller's package count is the packages it owns, not the server total
	let ownPackages = $state(null);
	$effect(() => {
		if ($session?.user?.role === 'reseller') api.get('/admin/packages').then((l) => (ownPackages = l.filter((p) => p.owner_id === $session.user.id).length)).catch(() => {});
	});
	// Favorites are stored on the server (PUT /account/preferences {favorites}, returned by
	// GET /auth/me). A browser that still has the pre-0.2 localStorage list migrates it once.
	// default favorites per role (R2-UX-01): never an administrator-only tool for a reseller
	const ADMIN_FAVS = ['create_account', 'list_accounts', 'packages', 'service_manager', 'php_versions', 'server_info'];
	const RESELLER_FAVS = ['create_account', 'list_accounts', 'packages', 'add_package'];
	let DEFAULT_FAVS = $derived($session?.user?.role === 'admin' ? ADMIN_FAVS : RESELLER_FAVS);
	const FAV_KEY = 'bp_admin_favs';
	const MAX_FAVS = 24;
	function legacyFavs() { try { const v = JSON.parse(localStorage.getItem(FAV_KEY) || 'null'); return Array.isArray(v) ? v : null; } catch { return null; } }
	function initialFavs() {
		const server = $session?.favorites;
		if (Array.isArray(server)) return server;
		const legacy = legacyFavs();
		if (legacy) { persistFavs(legacy.slice(0, MAX_FAVS)); return legacy.slice(0, MAX_FAVS); }
		return DEFAULT_FAVS;
	}
	async function persistFavs(ids) {
		try {
			await api.put('/account/preferences', { favorites: ids });
			localStorage.removeItem(FAV_KEY);
			session.update((s) => (s ? { ...s, favorites: ids } : s));
		} catch { /* keep the local list; retried on the next change */ }
	}
	let favIds = $state(initialFavs());
	let editFavs = $state(false);
	let addPick = $state('');
	let isAdmin = $derived($session?.user?.role === 'admin');
	let groups = $derived(visibleGroups('admin', $session?.user?.role, $session?.features));
	let available = $derived(groups.flatMap((g) => g.tools.map((x) => ({ ...x, group: g.id }))).filter((x, i, a) => a.findIndex((y) => y.id === x.id) === i));
	let favs = $derived(favIds.map((id) => available.find((x) => x.id === id)).filter(Boolean));
	let addable = $derived(available.filter((x) => !favIds.includes(x.id) && !x.soon));
	function saveFavs(ids) { favIds = ids.slice(0, MAX_FAVS); persistFavs(favIds); }
	function toggleFav(id) { saveFavs(favIds.includes(id) ? favIds.filter((x) => x !== id) : [...favIds, id]); }
	function moveFav(id, d) { const i = favIds.indexOf(id), j = i + d; if (j < 0 || j >= favIds.length) return; const a = [...favIds]; [a[i], a[j]] = [a[j], a[i]]; saveFavs(a); }

	function level(p, warn, crit) { return p >= crit ? 'red' : p >= warn ? 'amber' : 'green'; }
	let cpu = $derived(sum?.sys?.cpu_percent ?? 0);
	let mem = $derived(sum?.sys?.mem_total ? (sum.sys.mem_used / sum.sys.mem_total) * 100 : 0);
	let disk = $derived(sum?.sys?.disk_total ? (sum.sys.disk_used / sum.sys.disk_total) * 100 : 0);
	function toggle(id) { open = open.includes(id) ? open.filter((x) => x !== id) : [...open, id]; }
	const stepTool = { nameservers: '/settings', contact: '/settings', totp: '/security', package: '/packages?new=1' };
</script>

<h1 style="margin-bottom:16px">{$t('adash.title')}</h1>

{#if sum?.next_steps?.length && !hideSteps}
	<section class="steps">
		<div class="row sh"><h2 class="grow">{$t('adash.next_steps')}</h2><button class="linkbtn" onclick={() => { hideSteps = true; localStorage.setItem('bp_hide_steps', '1'); }}><X size={13} /> {$t('adash.dismiss')}</button></div>
		<div class="grid2">
			{#each sum.next_steps as s}
				<a class="card step" href={stepTool[s.key]}>
					<div class="grow"><b>{$t('adash.step_' + s.key)}</b><p class="muted small">{$t('adash.step_' + s.key + '_desc')}</p></div>
					<ArrowRight size={16} />
				</a>
			{/each}
		</div>
	</section>
{/if}

<div class="top">
	<section>
		<div class="row sh"><Star size={16} /><h2 class="grow">{$t('adash.favorites')}</h2>
			{#if editFavs}
				<button class="linkbtn" onclick={() => saveFavs(DEFAULT_FAVS)}><RotateCcw size={13} /> {$t('adash.reset_favorites')}</button>
				<button class="btn sm primary" onclick={() => (editFavs = false)} aria-pressed="true"><Check size={14} /> {$t('adash.done')}</button>
			{:else}
				<button class="btn sm" onclick={() => (editFavs = true)} aria-pressed="false"><Pencil size={13} /> {$t('adash.edit_favorites')}</button>
			{/if}
		</div>
		{#if editFavs}
			<form class="row addfav" onsubmit={(e) => { e.preventDefault(); if (addPick) { toggleFav(addPick); addPick = ''; } }}>
				<select bind:value={addPick} aria-label={$t('adash.add_favorite')}>
					<option value="">{$t('adash.choose_tool')}</option>
					{#each addable as x}<option value={x.id}>{$t('tools.' + x.id)} — {$t('groups.' + x.group)}</option>{/each}
				</select>
				<button class="btn" disabled={!addPick}><Plus size={14} /> {$t('adash.add_favorite')}</button>
			</form>
		{/if}
		<div class="grid2">
			{#each favs as f, i (f.id)}
				<div class="favwrap">
					<button class="card fav" onclick={() => openTool(f)} disabled={editFavs}>
						<ToolIcon icon={f.icon} size={34} />
						<div><b>{$t('tools.' + f.id)}</b><p class="muted small">{$t('tooldesc.' + f.id)}</p></div>
					</button>
					{#if editFavs}
						<div class="favctl">
							<button class="btn sm ghost" disabled={i === 0} onclick={() => moveFav(f.id, -1)} aria-label={$t('adash.move_up', { name: $t('tools.' + f.id) })}>↑</button>
							<button class="btn sm ghost" disabled={i === favs.length - 1} onclick={() => moveFav(f.id, 1)} aria-label={$t('adash.move_down', { name: $t('tools.' + f.id) })}>↓</button>
							<button class="btn sm ghost danger" onclick={() => toggleFav(f.id)} aria-label={$t('adash.remove_favorite', { name: $t('tools.' + f.id) })}><X size={14} /></button>
						</div>
					{/if}
				</div>
			{:else}
				<p class="muted">{$t('adash.no_favorites')}</p>
			{/each}
		</div>
	</section>
	<aside class="card">
		<div class="card-head"><h2>{$t('adash.statistics')}</h2></div>
		<div class="card-body">
			{#if isAdmin && sum?.sys}
				<ul class="dots">
					<li><span class="dot {level(cpu, 50, 90)}"></span> CPU <b>{cpu.toFixed(0)}%</b></li>
					<li><span class="dot {level(mem, 70, 95)}"></span> RAM <b>{mem.toFixed(0)}%</b></li>
					<li><span class="dot {level(disk, 50, 90)}"></span> {$t('adash.disk')} <b>{disk.toFixed(0)}%</b></li>
				</ul>
				<div class="kv small">
					<div>{$t('adash.memory')}</div><div>{$fmt.bytes(sum.sys.mem_used)} / {$fmt.bytes(sum.sys.mem_total)}</div>
					<div>{$t('adash.disk')}</div><div>{$fmt.bytes(sum.sys.disk_used)} / {$fmt.bytes(sum.sys.disk_total)}</div>
					<div>{$t('adash.uptime')}</div><div>{$fmt.duration(sum.sys.uptime_sec)}</div>
				</div>
			{/if}
			<div class="counts">
				<a href="/accounts"><Users size={16} /><b>{sum?.accounts ?? '…'}</b><span>{$t('adash.accounts')}</span></a>
				<a href="/accounts?status=suspended"><PauseCircle size={16} /><b>{sum?.suspended ?? '…'}</b><span>{$t('adash.suspended')}</span></a>
				{#if isAdmin}<a href="/accounts?role=reseller"><UserCog size={16} /><b>{sum?.resellers ?? '…'}</b><span>{$t('adash.resellers')}</span></a>{/if}
				<a href="/packages"><Package size={16} /><b>{(isAdmin ? sum?.packages : ownPackages) ?? '…'}</b><span>{$t('adash.packages')}</span></a>
			</div>
		</div>
	</aside>
</div>

<h2 class="sh" style="margin-top:24px">{$t('adash.tools')}</h2>
<div class="acc">
	{#each groups as g}
		{@const isOpen = open.includes(g.id)}
		<section class="card">
			<button class="card-head ah" aria-expanded={isOpen} onclick={() => toggle(g.id)}>
				<ToolIcon icon={g.icon} size={24} /><h2 class="grow">{$t('groups.' + g.id)}</h2>
				{#if isOpen}<ChevronDown size={18} />{:else}<ChevronRight size={18} />{/if}
			</button>
			{#if isOpen}
				<div class="tools">
					{#each [...g.tools.filter((x) => !x.soon), ...g.tools.filter((x) => x.soon)] as tool}
						<div class="toolrow">
							<button class="tool" class:soon={tool.soon} tabindex={tool.soon ? -1 : undefined} onclick={() => openTool(tool)}><ToolIcon icon={tool.icon} size={28} /><span>{$t('tools.' + tool.id)}{#if tool.soon} <em class="badge amber">{$t('common.soon')}</em>{/if}</span></button>
							{#if !tool.soon}<button class="star" class:on={favIds.includes(tool.id)} aria-pressed={favIds.includes(tool.id)} onclick={() => toggleFav(tool.id)}
								aria-label={favIds.includes(tool.id) ? $t('adash.remove_favorite', { name: $t('tools.' + tool.id) }) : $t('adash.add_favorite_named', { name: $t('tools.' + tool.id) })}><Star size={14} /></button>{/if}
						</div>
					{/each}
				</div>
			{/if}
		</section>
	{/each}
</div>

<style>
	.sh { margin-bottom: 10px; gap: 8px; }
	.steps { margin-bottom: 22px; }
	.step { display: flex; align-items: center; gap: 12px; padding: 14px 16px; color: var(--text); border-left: 3px solid var(--amber); }
	.step:hover { text-decoration: none; border-color: var(--accent); }
	.step p { margin: 2px 0 0; }
	.top { display: grid; grid-template-columns: minmax(0, 1fr) 300px; gap: 20px; align-items: start; }
	.fav { display: flex; gap: 14px; align-items: flex-start; padding: 14px 16px; text-align: left; font: inherit; color: var(--text); cursor: pointer; }
	.fav:hover:not(:disabled) { border-color: var(--primary); }
	.fav:disabled { cursor: default; opacity: 1; }
	.favwrap { position: relative; }
	.favwrap .fav { width: 100%; height: 100%; }
	.favctl { position: absolute; top: 6px; right: 6px; display: flex; gap: 2px; background: var(--card); border-radius: 6px; }
	.addfav { margin-bottom: 10px; flex-wrap: wrap; }
	.addfav select { flex: 1 1 220px; width: auto; }
	.toolrow { display: flex; align-items: center; }
	.toolrow .tool { flex: 1; min-width: 0; }
	.star { background: none; border: 0; padding: 6px; border-radius: 6px; color: var(--muted); cursor: pointer; opacity: 0.6; }
	.star:hover, .star:focus-visible { opacity: 1; background: var(--card-2); }
	.star.on { color: var(--amber); opacity: 1; }
	.star.on :global(svg) { fill: currentColor; }
	.fav b { color: var(--link); }
	.fav p { margin: 2px 0 0; }
	.dots { list-style: none; padding: 0; margin: 0 0 10px; display: flex; gap: 14px; flex-wrap: wrap; }
	.dot { display: inline-block; width: 9px; height: 9px; border-radius: 50%; margin-right: 4px; }
	.dot.green { background: var(--green); }
	.dot.amber { background: var(--amber); }
	.dot.red { background: var(--red); }
	.counts { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-top: 14px; }
	.counts a { display: flex; flex-direction: column; align-items: flex-start; gap: 2px; padding: 10px; border: 1px solid var(--border); border-radius: 6px; color: var(--text); }
	.counts a:hover { text-decoration: none; border-color: var(--primary); }
	.counts b { font-size: 20px; font-weight: 400; }
	.counts span { font-size: 12px; color: var(--muted); }
	.acc { display: flex; flex-direction: column; gap: 8px; }
	.ah { width: 100%; background: none; border: 0; color: var(--text); font: inherit; cursor: pointer; text-align: left; }
	.tools { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 4px 12px; padding: 10px 14px; border-top: 1px solid var(--border); }
	.tool { display: flex; align-items: center; gap: 10px; padding: 8px; background: none; border: 0; color: var(--link); font: inherit; text-align: left; cursor: pointer; border-radius: 6px; }
	.tool:hover { background: var(--card-2); }
	.tool em { font-style: normal; font-size: 10px; }
	.tool.soon { color: var(--text-2); }
	@media (max-width: 1100px) { .top { grid-template-columns: 1fr; } .tools { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
	@media (max-width: 600px) { .tools { grid-template-columns: 1fr; } .sh { flex-wrap: wrap; } }
</style>
