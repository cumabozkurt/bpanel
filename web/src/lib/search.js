// Search helpers shared by the top bar, the sidebar filter and the command palette.
// Matching is accent- and Turkish-insensitive (ş→s, ı→i, ğ→g, ç→c, ö→o, ü→u, İ→i),
// works across languages (EN and TR tool names both match) and knows a few synonyms.
import { translate, languages } from './i18n/index.js';

const TR_MAP = { ş: 's', Ş: 's', ı: 'i', İ: 'i', ğ: 'g', Ğ: 'g', ç: 'c', Ç: 'c', ö: 'o', Ö: 'o', ü: 'u', Ü: 'u' };

/** Lower-case, strip accents, fold Turkish letters to ASCII. */
export function norm(s) {
	return String(s ?? '')
		.replace(/[şŞıİğĞçÇöÖüÜ]/g, (c) => TR_MAP[c])
		.toLowerCase()
		.normalize('NFD')
		.replace(/[\u0300-\u036f]/g, '');
}

/** Turkish-aware transliteration to [a-z0-9] (used for auto-generated usernames). */
export function translit(s) {
	return norm(s).replace(/[^a-z0-9]/g, '');
}

// Extra words that should find a tool, in both languages (already normalised).
const SYN = {
	email_accounts: 'eposta e-posta posta mail mailbox hesap inbox',
	forwarders: 'yonlendirme yonlendirici forward alias',
	default_address: 'catch all varsayilan',
	webmail: 'web posta roundcube',
	deliverability: 'teslim spf dkim dmarc',
	file_manager: 'dosya dosyalar files upload yukle editor',
	disk_usage: 'disk alan kota quota space',
	ftp_accounts: 'ftp sftp ssh',
	backups: 'yedek yedekleme backup restore geri yukle',
	file_restore: 'geri yukle restore yedek',
	mysql_databases: 'db database veritabani mysql mariadb sql',
	db_wizard: 'db sihirbaz wizard veritabani',
	phpmyadmin: 'pma sql db veritabani',
	domains: 'alan adi domain site addon',
	subdomains: 'alt alan subdomain',
	aliases: 'park takma alias',
	redirects: 'yonlendirme redirect 301 302',
	zone_editor: 'dns kayit record mx a cname txt bolge zone',
	errors: 'hata log kayit',
	raw_access: 'erisim log ziyaret',
	visitors: 'ziyaretci visitor',
	ssl_status: 'ssl tls https sertifika certificate autossl lets encrypt',
	two_factor: '2fa iki adim totp dogrulama guvenlik security',
	ssh_access: 'ssh sftp anahtar key',
	multiphp: 'php surum version',
	cron_jobs: 'cron zamanlanmis gorev schedule task',
	password_security: 'sifre parola password guvenlik',
	change_language: 'dil language turkce english',
	theme: 'tema karanlik koyu dark light',
	contact_info: 'iletisim contact eposta',
	basic_setup: 'ayar ayarlar settings nameserver',
	server_info: 'sunucu bilgi server cpu ram',
	audit_log: 'denetim kayit log gecmis history',
	list_accounts: 'hesap hesaplar account users kullanici',
	list_suspended: 'askiya suspended',
	create_account: 'yeni hesap olustur new account',
	manage_suspension: 'askiya al suspend',
	terminate_account: 'sil kapat terminate delete',
	change_password: 'sifre parola password',
	list_resellers: 'bayi reseller',
	create_reseller: 'bayi reseller yeni',
	packages: 'paket plan package',
	add_package: 'paket yeni plan',
	php_versions: 'php surum fpm',
	service_manager: 'servis hizmet service nginx apache',
	restart_services: 'yeniden baslat restart servis',
	nameservers: 'ns ad sunucusu nameserver',
	api_docs: 'api openapi rest dokuman'
};

/** All searchable text for a tool: its name in every language, its group, keywords and synonyms. */
export function toolHaystack(tool) {
	const parts = [tool.kw || '', SYN[tool.id] || ''];
	for (const l of languages) {
		parts.push(translate('tools.' + tool.id, undefined, l.code));
		if (tool.group) parts.push(translate('groups.' + tool.group, undefined, l.code));
	}
	return norm(parts.join(' '));
}

/** Every whitespace-separated query token must appear in the haystack. */
export function matches(haystack, query) {
	const toks = norm(query).split(/\s+/).filter(Boolean);
	if (!toks.length) return false;
	const h = norm(haystack);
	return toks.every((t) => h.includes(t));
}

/** Rank: label prefix > word prefix > substring. */
export function score(label, query) {
	const l = norm(label), q = norm(query).trim();
	if (l.startsWith(q)) return 0;
	if (l.split(/[\s._@-]+/).some((w) => w.startsWith(q))) return 1;
	return l.includes(q) ? 2 : 3;
}
