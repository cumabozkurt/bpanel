<script>
	import { onMount } from 'svelte';
	import { page } from '$app/state';
	import { goto } from '$app/navigation';
	import { meta, session, loadMeta, loadSession, applyTheme } from './stores.js';
	import { t } from './i18n/index.js';
	import { match } from './router.js';
	import { api } from './api.js';
	import { installValidationMessages } from './a11y.js';
	import Shell from './components/Shell.svelte';
	import Toasts from './components/Toasts.svelte';
	import CommandPalette from './components/CommandPalette.svelte';
	import Login from './pages/Login.svelte';
	import NotFound from './pages/NotFound.svelte';
	import AdminOnly from './pages/AdminOnly.svelte';
	import { pageTitle } from './stores.js';
	import { ADMIN_ONLY_PATHS, isAdminOnlyTool } from './tools.js';

	// Route-level code splitting: every page is its own chunk, loaded on first visit.
	const P = {
		Security: () => import('./pages/Security.svelte'),
		Preferences: () => import('./pages/Preferences.svelte')
	};
	const routes = {
		user: [
			['/', () => import('./pages/user/Dashboard.svelte')], ['/domains', () => import('./pages/user/Domains.svelte')],
			['/dns', () => import('./pages/user/ZoneList.svelte')], ['/dns/:domain', () => import('./pages/user/ZoneEditor.svelte')],
			['/email/accounts', () => import('./pages/user/EmailAccounts.svelte')], ['/email/forwarders', () => import('./pages/user/Forwarders.svelte')], ['/email/autoresponders', () => import('./pages/user/Autoresponders.svelte')], ['/email/filters', () => import('./pages/user/EmailFilters.svelte')], ['/email/spam', () => import('./pages/user/SpamFilters.svelte')], ['/email/track', () => import('./pages/user/TrackDelivery.svelte')], ['/email/lists', () => import('./pages/user/MailingLists.svelte')], ['/dnsx', () => import('./pages/user/DnsTools.svelte')],
			['/email/deliverability', () => import('./pages/user/Deliverability.svelte')], ['/databases', () => import('./pages/user/Databases.svelte')], ['/databases/remote', () => import('./pages/user/RemoteMySQL.svelte')], ['/databases/processes', () => import('./pages/user/DBProcesses.svelte')], ['/postgresql', () => import('./pages/user/PostgreSQL.svelte')],
			['/files', () => import('./pages/user/FileManager.svelte')], ['/ftp', () => import('./pages/user/FTP.svelte')], ['/cron', () => import('./pages/user/Cron.svelte')],
			['/ssl', () => import('./pages/user/SSL.svelte')], ['/php', () => import('./pages/user/PHP.svelte')], ['/disk', () => import('./pages/user/Disk.svelte')], ['/usage', () => import('./pages/user/Usage.svelte')], ['/bandwidth', () => import('./pages/user/Bandwidth.svelte')], ['/php-ini', () => import('./pages/user/PHPIni.svelte')], ['/api-tokens', () => import('./pages/user/ApiTokens.svelte')], ['/modsecurity', () => import('./pages/user/ModSecurity.svelte')], ['/malware-scans', () => import('./pages/user/MalwareScans.svelte')], ['/web/:section', () => import('./pages/user/WebExtras.svelte')], ['/git', () => import('./pages/user/Git.svelte')], ['/git/:id', () => import('./pages/user/GitRepo.svelte')], ['/terminal', () => import('./pages/user/Terminal.svelte')], ['/track-dns', () => import('./pages/user/TrackDNS.svelte')], ['/ddns', () => import('./pages/user/DynamicDNS.svelte')], ['/apps', () => import('./pages/user/Apps.svelte')], ['/installer', () => import('./pages/user/Installer.svelte')], ['/wordpress', () => import('./pages/user/WordPress.svelte')],
			['/logs/:kind', () => import('./pages/user/Logs.svelte')], ['/backups', () => import('./pages/user/Backups.svelte')], ['/contact-email', () => import('./pages/user/ContactEmail.svelte')], ['/user-manager', () => import('./pages/user/UserManager.svelte')],
			['/stats/visitors', () => import('./pages/user/Visitors.svelte')], ['/email/routing', () => import('./pages/user/EmailRouting.svelte')], ['/email/boxtrapper', () => import('./pages/user/BoxTrapper.svelte')], ['/email/encryption', () => import('./pages/user/Encryption.svelte')], ['/calendars', () => import('./pages/user/Calendars.svelte')], ['/ssh-keys', () => import('./pages/user/SSHKeys.svelte')], ['/site-publisher', () => import('./pages/user/SitePublisher.svelte')], ['/images', () => import('./pages/user/Images.svelte')], ['/postgresql/browser', () => import('./pages/user/PgBrowser.svelte')], ['/cloudflare', () => import('./pages/user/Cloudflare.svelte')], // v1.1
			['/security', P.Security], ['/preferences', P.Preferences]
		],
		admin: [
			['/', () => import('./pages/admin/Dashboard.svelte')], ['/accounts', () => import('./pages/admin/Accounts.svelte')],
			['/accounts/new', () => import('./pages/admin/CreateAccount.svelte')], ['/packages', () => import('./pages/admin/Packages.svelte')], ['/limits', () => import('./pages/admin/Isolation.svelte')], ['/shield', () => import('./pages/admin/Shield.svelte')], ['/firewall', () => import('./pages/admin/Firewall.svelte')], ['/brute-force', () => import('./pages/admin/BruteForce.svelte')], ['/bandwidth', () => import('./pages/admin/Bandwidth.svelte')],
			['/services', () => import('./pages/admin/Services.svelte')], ['/integrations', () => import('./pages/admin/Integrations.svelte')], ['/php', () => import('./pages/admin/PHP.svelte')],
			['/server', () => import('./pages/admin/ServerInfo.svelte')], ['/audit', () => import('./pages/admin/Audit.svelte')], ['/webhooks', () => import('./pages/admin/Webhooks.svelte')], ['/events', () => import('./pages/admin/Events.svelte')], ['/backups', () => import('./pages/admin/Backups.svelte')], ['/db-settings', () => import('./pages/admin/DBSettings.svelte')], ['/dns-cluster', () => import('./pages/admin/DnsCluster.svelte')], ['/plugins', () => import('./pages/admin/Plugins.svelte')], ['/servers', () => import('./pages/admin/Servers.svelte')], ['/transfer', () => import('./pages/admin/TransferTool.svelte')],
			['/settings', () => import('./pages/admin/Settings.svelte')], ['/modify-account', () => import('./pages/admin/ModifyAccount.svelte')], ['/edit-reseller', () => import('./pages/admin/EditReseller.svelte')], ['/update-prefs', () => import('./pages/admin/UpdatePrefs.svelte')], ['/monitoring', () => import('./pages/admin/Monitoring.svelte')], ['/alerts', () => import('./pages/admin/Alerts.svelte')],
			['/mail-queue', () => import('./pages/admin/MailQueue.svelte')], ['/mail-troubleshooter', () => import('./pages/admin/MailTroubleshooter.svelte')], ['/ips', () => import('./pages/admin/IPFunctions.svelte')], ['/hostname', () => import('./pages/admin/Hostname.svelte')], ['/tweak-settings', () => import('./pages/admin/TweakSettings.svelte')], ['/php-extensions', () => import('./pages/admin/PHPExtensions.svelte')], ['/billing', () => import('./pages/admin/Billing.svelte')], // v1.1
			['/security', P.Security], ['/preferences', P.Preferences]
		]
	};
	const loaded = new Map(); // loader -> component, so a revisit renders without waiting

	let ready = $state(false);
	let sys = $state(null);
	let realm = $derived($meta?.realm ?? 'user');
	let path = $derived(page.url.pathname.replace(/\/+$/, '') || '/');
	// Remount the page when the path OR the query string changes (/accounts?status=… -> /accounts?role=…),
	// so pages that read ?new=1 / ?kind= / ?q= on init always reflect the URL. The File Manager keeps its
	// own ?path= in sync without a remount.
	let viewKey = $derived(path === '/files' ? path : path + page.url.search);
	let isLogin = $derived(path === '/login' || path.startsWith('/login/once/'));
	let role = $derived($session?.user?.role);
	let resolved = $derived.by(() => {
		for (const [pat, load] of routes[realm] ?? []) {
			const params = match(pat, path);
			if (!params) continue;
			// R2-UX-01: resellers share the admin port but never get the administrator's tools
			if (realm === 'admin' && role && role !== 'admin' && (ADMIN_ONLY_PATHS.includes(path) || (pat === '/tool/:id' && isAdminOnlyTool(params.id)))) return { comp: AdminOnly, params };
			return { load, params };
		}
		return { comp: NotFound, params: {} };
	});
	let comp = $state.raw(null);
	let compFor = $state.raw(null); // raw: compared by identity with resolved
	$effect(() => {
		const r = resolved;
		if (r.comp) { comp = r.comp; compFor = r; return; }
		if (loaded.has(r.load)) { comp = loaded.get(r.load); compFor = r; return; }
		r.load().then((m) => { loaded.set(r.load, m.default); if (resolved === r) { comp = m.default; compFor = r; } }).catch(() => { comp = NotFound; compFor = r; });
	});

	onMount(async () => {
		applyTheme(localStorage.getItem('bp_theme') || 'light');
		installValidationMessages();
		try { await loadMeta(); } catch {}
		await loadSession();
		ready = true;
		window.addEventListener('bp:unauthenticated', () => { session.set(null); goto('/login?next=' + encodeURIComponent(location.pathname)); });
	});

	$effect(() => {
		if (!ready) return;
		if (!$session && !isLogin) goto('/login?next=' + encodeURIComponent(path + page.url.search), { replaceState: true });
		if ($session && path === '/login') goto(page.url.searchParams.get('next') || '/', { replaceState: true });
	});

	$effect(() => {
		if (ready && $session && realm === 'admin' && $session.user.role === 'admin') {
			api.get('/admin/server').then((r) => (sys = r.sys)).catch(() => {});
		}
	});

	// After a client-side navigation, move focus to the new page (screen readers announce it).
	let lastKey = '';
	$effect(() => {
		const k = viewKey;
		if (!ready || !$session) return;
		if (lastKey && lastKey !== k) {
			const a = document.activeElement;
			if (!a || a === document.body || a.closest('aside') || a.closest('.results')) {
				// R2-UX-07: a dialog the new page opened (…?wizard=1, ?new=1) keeps its focus
				setTimeout(() => {
					const act = document.activeElement;
					if (document.querySelector('[role=dialog][aria-modal=true]') || act?.closest?.('[role=dialog]')) return;
					if (act && act !== document.body && act.closest?.('main')) return;
					document.getElementById('main-content')?.focus({ preventScroll: true });
				}, 60);
			}
		}
		lastKey = k;
	});

	// R2-UX-24: per-route title "<page> — <panel> — BOZKURT PANEL" (PageHead publishes <page>)
	$effect(() => {
		const name = realm === 'admin' ? $t('app.admin_title') : $t('app.user_title');
		const pageName = isLogin || !$session ? $t('login.submit') : $pageTitle;
		document.title = [pageName, name, 'BOZKURT PANEL'].filter(Boolean).join(' — ');
	});
	// R2-UX-36: "Follow system" follows later OS theme switches too
	onMount(() => {
		const mq = matchMedia('(prefers-color-scheme: dark)');
		const on = () => { if (localStorage.getItem('bp_theme') === 'system') applyTheme('system'); };
		mq.addEventListener?.('change', on);
		return () => mq.removeEventListener?.('change', on);
	});
</script>

{#if !ready}
	<div class="boot" aria-busy="true"></div>
{:else if isLogin || !$session}
	<Login {realm} />
{:else}
	<Shell {realm} {sys}>
		{#key viewKey}
			{#if comp && compFor === resolved}
				{@const C = comp}
				<C params={resolved.params} {realm} />
			{:else}
				<p class="muted loading" aria-busy="true">{$t('common.loading')}</p>
			{/if}
		{/key}
	</Shell>
	<CommandPalette {realm} />
{/if}
<Toasts />

<style>
	.boot { min-height: 100vh; background: var(--bg); }
	.loading { padding: 24px 0; }
</style>
