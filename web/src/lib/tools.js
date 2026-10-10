// Tool registry: drives the user tool grid, the admin menu, search and the
// command palette. Names come from i18n keys tools.<id>; "soon" tools are on
// the roadmap and open a short explanation page instead of a feature.
import {
	Mail, Forward, AtSign, Reply, ShieldCheck, Inbox, Filter, ShieldAlert, Users, HardDrive, FolderOpen,
	PieChart, Server, Archive, History, Lock, GitBranch, Database, Wand2, Table2, Globe, Link2, Waypoints,
	Network, ArrowRightLeft, FileWarning, FileText, BarChart3, Gauge, KeyRound, Smartphone, Ban, Image,
	Code2, Settings2, Boxes, Puzzle, Clock, Terminal, Search, Languages, Contact, Palette, UserCog, Activity,
	Package, UserPlus, UserX, PauseCircle, ListChecks, Cpu, RefreshCw, Info, ScrollText, Settings, BookOpen,
	Truck, LayoutGrid, Layers, Shield, Webhook, MonitorCog, PlugZap
} from '@lucide/svelte';

export const userGroups = [
	{ id: 'email', icon: Mail, tools: [
		{ id: 'email_accounts', icon: Mail, to: '/email/accounts', kw: 'mailbox imap pop', feature: 'mail' },
		{ id: 'forwarders', icon: Forward, to: '/email/forwarders', kw: 'alias redirect', feature: 'mail' },
		{ id: 'default_address', icon: AtSign, to: '/email/forwarders?catchall=1', kw: 'catch-all catchall', feature: 'mail' },
		{ id: 'webmail', icon: Inbox, action: 'webmail', kw: 'roundcube', feature: 'webmail' },
		{ id: 'deliverability', icon: ShieldCheck, to: '/email/deliverability', kw: 'spf dkim dmarc', feature: 'mail' },
		{ id: 'email_disk_usage', icon: PieChart, to: '/email/accounts?sort=-usage', kw: 'quota', feature: 'mail' },
		{ id: 'autoresponders', icon: Reply, to: '/email/autoresponders', kw: 'vacation out of office sieve', feature: 'mail' },
		{ id: 'email_filters', icon: Filter, to: '/email/filters', kw: 'sieve rules folder', feature: 'mail' },
		{ id: 'spam_filters', icon: ShieldAlert, to: '/email/spam', kw: 'rspamd junk whitelist blacklist', feature: 'mail' },
		{ id: 'mailing_lists', icon: Users, to: '/email/lists', kw: 'mlmmj list newsletter subscribers', feature: 'mail' },
		{ id: 'track_delivery', icon: Truck, to: '/email/track', kw: 'mail log bounce postfix', feature: 'mail' }
	] },
	{ id: 'files', icon: FolderOpen, tools: [
		{ id: 'file_manager', icon: FolderOpen, to: '/files', kw: 'upload edit zip chmod' },
		{ id: 'disk_usage', icon: PieChart, to: '/disk', kw: 'space quota' },
		{ id: 'resource_usage', icon: Gauge, to: '/usage', kw: 'cpu memory ram io processes limits kaynak' },
		{ id: 'ftp_accounts', icon: Server, to: '/ftp', kw: 'sftp', feature: 'ftp' },
		{ id: 'backups', icon: Archive, to: '/backups', kw: 'restic snapshot' },
		{ id: 'file_restore', icon: History, to: '/backups', kw: 'restore' },
		{ id: 'directory_privacy', icon: Lock, to: '/web/privacy', kw: 'password protect htpasswd basic auth parola koruma' },
		{ id: 'git', icon: GitBranch, to: '/git', kw: 'git version control repository clone deploy depo sürüm' }
	] },
	{ id: 'databases', icon: Database, tools: [
		{ id: 'mysql_databases', icon: Database, to: '/databases', kw: 'mariadb mysql user' },
		{ id: 'db_wizard', icon: Wand2, to: '/databases?wizard=1', kw: 'wizard' },
		{ id: 'phpmyadmin', icon: Table2, action: 'phpmyadmin', kw: 'sql' },
		{ id: 'remote_mysql', icon: Network, to: '/databases/remote', kw: 'remote mysql mariadb host ip uzak' },
		{ id: 'postgresql', icon: Database, to: '/postgresql', kw: 'postgres pgsql psql' },
		{ id: 'db_processes', icon: Activity, to: '/databases/processes', kw: 'processlist slow query kill sorgu' }
	] },
	{ id: 'domains', icon: Globe, tools: [
		{ id: 'domains', icon: Globe, to: '/domains', kw: 'addon' },
		{ id: 'subdomains', icon: Waypoints, to: '/domains?kind=sub', kw: 'sub' },
		{ id: 'aliases', icon: Link2, to: '/domains?kind=alias', kw: 'parked park' },
		{ id: 'redirects', icon: ArrowRightLeft, to: '/domains?redirects=1', kw: '301' },
		{ id: 'zone_editor', icon: Network, to: '/dns', kw: 'dns record mx txt cname', feature: 'dns' },
		{ id: 'dns_tools', icon: Network, to: '/dnsx', kw: 'dnssec ds import export bind zone file history revert check', feature: 'dns' },
		{ id: 'dynamic_dns', icon: RefreshCw, to: '/ddns', kw: 'ddns dynamic dns dyndns home ip dinamik' }
	] },
	{ id: 'metrics', icon: BarChart3, tools: [
		{ id: 'errors', icon: FileWarning, to: '/logs/error', kw: 'error log' },
		{ id: 'raw_access', icon: FileText, to: '/logs/access', kw: 'access log visitors' },
		{ id: 'visitors', icon: Users, to: '/logs/access', kw: 'visits' },
		{ id: 'bandwidth', icon: Activity, to: '/bandwidth', kw: 'traffic transfer trafik bant genişliği' },
		{ id: 'resource_usage', icon: Gauge, to: '/usage', kw: 'cpu memory io kaynak kullanımı' }
	] },
	{ id: 'security', icon: Shield, tools: [
		{ id: 'ssl_status', icon: ShieldCheck, to: '/ssl', kw: 'autossl lets encrypt https certificate' },
		{ id: 'two_factor', icon: Smartphone, to: '/security', kw: '2fa totp' },
		{ id: 'ssh_access', icon: KeyRound, to: '/ftp', kw: 'sftp ssh' },
		{ id: 'ip_blocker', icon: Ban, to: '/web/ip-blocker', kw: 'deny block ip cidr engelle' },
		{ id: 'hotlink', icon: Image, to: '/web/hotlink', kw: 'referer referrer bandwidth images' },
		{ id: 'api_tokens', icon: Webhook, to: '/api-tokens', kw: 'api token bearer anahtar' },
		{ id: 'modsecurity', icon: ShieldAlert, to: '/modsecurity', kw: 'waf crs owasp güvenlik duvarı' },
		{ id: 'malware_scans', icon: ShieldCheck, to: '/malware-scans', kw: 'malware virus shield antivirus quarantine zararlı tarama' }
	] },
	{ id: 'software', icon: Boxes, tools: [
		{ id: 'multiphp', icon: Code2, to: '/php', kw: 'php version' },
		{ id: 'php_ini', icon: Settings2, to: '/php-ini', kw: 'php.ini memory_limit upload timezone' },
		{ id: 'wordpress', icon: LayoutGrid, to: '/wordpress', kw: 'wp blog cms maintenance wp-cli bakım' },
		{ id: 'app_installer', icon: Puzzle, to: '/installer', kw: 'softaculous joomla drupal nextcloud install kurulum uygulama' },
		{ id: 'nodejs', icon: Layers, to: '/apps', kw: 'node npm python pip wsgi application manager uygulama yöneticisi' }
	] },
	{ id: 'advanced', icon: Settings2, tools: [
		{ id: 'cron_jobs', icon: Clock, to: '/cron', kw: 'schedule' },
		{ id: 'terminal', icon: Terminal, to: '/terminal', kw: 'shell ssh console bash konsol' },
		{ id: 'track_dns', icon: Search, to: '/track-dns', kw: 'dig nslookup traceroute lookup dns izle' },
		{ id: 'error_pages', icon: FileWarning, to: '/web/error-pages', kw: '404 500 errordocument hata sayfası' },
		{ id: 'mime_types', icon: FileText, to: '/web/mime', kw: 'content-type addtype' }
	] },
	{ id: 'preferences', icon: UserCog, tools: [
		{ id: 'password_security', icon: KeyRound, to: '/security', kw: 'password' },
		{ id: 'change_language', icon: Languages, to: '/preferences', kw: 'language dil' },
		{ id: 'theme', icon: Palette, to: '/preferences', kw: 'dark mode' },
		{ id: 'contact_info', icon: Contact, to: '/contact-email', kw: 'email' },
		{ id: 'user_manager', icon: Users, to: '/user-manager', kw: 'sub-users subaccounts email ftp alt kullanıcı' }
	] }
];

export const adminGroups = [
	{ id: 'server_config', icon: MonitorCog, tools: [
		{ id: 'basic_setup', icon: Settings, to: '/settings', kw: 'nameserver ip contact language', adminOnly: true },
		{ id: 'server_info', icon: Info, to: '/server', kw: 'cpu memory kernel', adminOnly: true },
		{ id: 'update_prefs', icon: RefreshCw, to: '/update-prefs', kw: 'apt dnf upgrade security reboot güncelleme', adminOnly: true },
		{ id: 'monitoring', icon: Activity, to: '/monitoring', kw: 'health smart raid ntp prometheus grafana fim integrity retention izleme sağlık', adminOnly: true },
		{ id: 'alerts', icon: FileWarning, to: '/alerts', kw: 'alert incident telegram slack discord notification uyarı olay bildirim', adminOnly: true }
	] },
	{ id: 'security_center', icon: Shield, tools: [
		{ id: 'two_factor', icon: Smartphone, to: '/security', kw: '2fa totp password' },
		{ id: 'audit_log', icon: ScrollText, to: '/audit', kw: 'history log', adminOnly: true },
		{ id: 'sec_events', icon: Activity, to: '/events', kw: 'events security olay' },
		{ id: 'bpanel_shield', icon: ShieldCheck, to: '/shield', kw: 'malware virus clamav yara quarantine antivirus zararlı karantina' },
		{ id: 'webhooks', icon: Webhook, to: '/webhooks', kw: 'webhook hmac notify bildirim', adminOnly: true },
		{ id: 'brute_force', icon: ShieldAlert, to: '/brute-force', adminOnly: true, kw: 'fail2ban cphulk ban unban allowlist kaba kuvvet' },
		{ id: 'firewall', icon: Ban, to: '/firewall', adminOnly: true, kw: 'nftables block ip waf modsecurity crs güvenlik duvarı' }
	] },
	{ id: 'account_info', icon: ListChecks, tools: [
		{ id: 'list_accounts', icon: ListChecks, to: '/accounts', kw: 'users' },
		{ id: 'list_suspended', icon: PauseCircle, to: '/accounts?status=suspended', kw: 'suspend' },
		{ id: 'bandwidth', icon: Activity, to: '/bandwidth', kw: 'traffic transfer trafik' }
	] },
	{ id: 'account_functions', icon: UserPlus, tools: [
		{ id: 'create_account', icon: UserPlus, to: '/accounts/new', kw: 'new add' },
		{ id: 'manage_suspension', icon: PauseCircle, to: '/accounts?action=suspend', kw: 'suspend unsuspend' },
		{ id: 'terminate_account', icon: UserX, to: '/accounts?action=terminate', kw: 'delete remove' },
		{ id: 'change_password', icon: KeyRound, to: '/accounts?action=password', kw: 'password' },
		{ id: 'modify_account', icon: UserCog, to: '/modify-account', kw: 'shell ssh owner package overrides hesap değiştir' },
		{ id: 'change_contact_email', icon: Contact, to: '/modify-account?focus=email', kw: 'email contact iletişim' }
	] },
	{ id: 'resellers', icon: Users, adminOnly: true, tools: [
		{ id: 'list_resellers', icon: Users, to: '/accounts?role=reseller', kw: 'reseller' },
		{ id: 'create_reseller', icon: UserPlus, to: '/accounts/new?role=reseller', kw: 'reseller new' },
		{ id: 'edit_reseller', icon: UserCog, to: '/edit-reseller', kw: 'reseller limits acl privileges bayi', adminOnly: true }
	] },
	{ id: 'packages', icon: Package, tools: [
		{ id: 'packages', icon: Package, to: '/packages', kw: 'plan limits' },
		{ id: 'add_package', icon: Package, to: '/packages?new=1', kw: 'new plan' },
		{ id: 'resource_limits', icon: Gauge, to: '/limits', kw: 'cpu memory io cgroup isolation limit profile kaynak' }
	] },
	{ id: 'service_config', icon: Cpu, adminOnly: true, tools: [
		{ id: 'php_versions', icon: Code2, to: '/php', kw: 'multiphp fpm' },
		{ id: 'service_manager', icon: Cpu, to: '/services', kw: 'nginx apache mariadb' },
		{ id: 'restart_services', icon: RefreshCw, to: '/services', kw: 'restart' },
		{ id: 'integrations', icon: Cpu, to: '/integrations', kw: 'providers license imunify monarx detect' },
		{ id: 'db_settings', icon: Database, to: '/db-settings', kw: 'mysql postgresql remote 3306 max connections veritabanı', adminOnly: true },
		{ id: 'servers', icon: Server, to: '/servers', kw: 'multi server node cluster mtls agent sunucu düğüm', adminOnly: true }
	] },
	{ id: 'dns_functions', icon: Network, adminOnly: true, tools: [
		{ id: 'nameservers', icon: Network, to: '/settings', kw: 'ns' },
		{ id: 'dns_cluster', icon: Waypoints, to: '/dns-cluster', kw: 'powerdns secondary slave axfr notify replication ikincil küme' }
	] },
	{ id: 'backup', icon: Archive, adminOnly: true, tools: [
		{ id: 'backup_config', icon: Archive, to: '/backups', kw: 'restic retention verify yedek saklama' },
		{ id: 'transfer_tool', icon: ArrowRightLeft, to: '/transfer', kw: 'cpanel cpmove whm migration import export restore taşıma aktarım', adminOnly: true }
	] },
	{ id: 'development', icon: Code2, tools: [
		{ id: 'api_docs', icon: BookOpen, href: '/openapi.json', kw: 'openapi rest' },
		{ id: 'plugins', icon: PlugZap, to: '/plugins', adminOnly: true, kw: 'plugin extension addon ed25519 eklenti' }
	] }
];

// Role filter (R2-UX-01/02): a group or tool marked adminOnly is never shown to a reseller,
// neither in the menu, the dashboard, favorites, search nor the command palette.
const canSee = (x, role) => !x.adminOnly || role === 'admin';
// Install-profile filter (R2-SYS-16): a tool tagged feature: 'mail' | 'dns' | 'ftp' | 'webmail' is hidden when
// /auth/me reports that feature as not installed (features[name] === false); unknown = shown.
const installed = (x, features) => !x.feature || !features || features[x.feature] !== false;

/** Groups (with their tools) the given role may see on this server; empty groups are dropped. */
export function visibleGroups(realm, role, features) {
	const groups = realm === 'admin' ? adminGroups : userGroups;
	return groups
		.filter((g) => realm !== 'admin' || canSee(g, role))
		.map((g) => ({ ...g, tools: g.tools.filter((x) => (realm !== 'admin' || canSee(x, role)) && installed(x, features)) }))
		.filter((g) => g.tools.length);
}

/** Every tool of the realm, flattened with its group id; role applies the admin-only filter, features the profile filter. */
export function allTools(realm, role = 'admin', features) {
	return visibleGroups(realm, role, features).flatMap((g) => g.tools.map((t) => ({ ...t, group: g.id })));
}

/** Is a feature installed? (missing flag = yes, for servers older than v0.3) */
export const hasFeature = (features, name) => !features || features[name] !== false;

/** Admin-realm paths that only the server administrator may open (route guard in App.svelte). */
export const ADMIN_ONLY_PATHS = ['/services', '/integrations', '/php', '/server', '/audit', '/settings', '/brute-force', '/edit-reseller', '/update-prefs', '/monitoring', '/alerts', '/db-settings', '/servers', '/dns-cluster', '/plugins', '/transfer'];
export function isAdminOnlyTool(id) {
	for (const g of adminGroups) for (const x of g.tools) if (x.id === id) return !!(g.adminOnly || x.adminOnly);
	return false;
}
