package installer

// Installer output in English (default) and Turkish. Add a language by
// adding a map with the same keys.
var messages = map[string]map[string]string{
	"en": {
		"banner":             "BOZKURT PANEL %s installer — %s — profile: %s",
		"stage_start":        "[%d/%d] %s …",
		"stage_skip":         "[%d/%d] %s — already done, skipping",
		"stage_ok":           "  ✔ %s (%s)",
		"stage_fail":         "  ✘ %s failed: %v",
		"resume_hint":        "Fix the problem and run the installer again; it continues from this stage. Full log: %s",
		"stage.preflight":    "Preflight checks",
		"stage.repos":        "Package repositories",
		"stage.packages":     "Packages",
		"stage.system":       "System preparation (users, quota, limits)",
		"stage.configs":      "Service configuration",
		"stage.panel":        "Panel services",
		"stage.hostname-ssl": "Hostname certificate",
		"stage.selftest":     "Self-test",
		"stage.upgrade":      "Upgrade (packages, hardening, panel, migrations)",
		"not_root":           "the installer must run as root",
		"apt_wait":           "  … waiting for another package manager to finish (%s is locked)",
		"unsupported":        "%s is not a supported system (Ubuntu 24.04, AlmaLinux 9); use --allow-unsupported to try anyway",
		"not_fresh":          "this server is not fresh: %s (use --force to continue at your own risk)",
		"requirements":       "this server does not meet the minimum requirements: %s",
		"upgrade_start":      "Upgrading BOZKURT PANEL %s → %s (profile %s); websites, mail and data stay online",
		"upgrade_current":    "BOZKURT PANEL %s is already installed and up to date; re-applying the configuration (idempotent)",
		"upgrade_done":       "✔ BOZKURT PANEL upgraded to %s",
		"upgrade_none":       "BOZKURT PANEL is not installed on this server (no completed installation in %s); run install first",
		"upgrade_newer":      "the installed version %s is newer than this installer (%s); refusing to downgrade",
		"done_title":         "✔ BOZKURT PANEL %s is installed",
		"done_user":          "  User panel   : https://%s:2083/   (HTTP 2082 redirects)",
		"done_admin":         "  Admin panel  : https://%s:2087/   (HTTP 2086 redirects)",
		"done_webmail":       "  Webmail      : https://%s:2096/   (HTTP 2095 redirects)",
		"done_login":         "  One-time login link (15 min): %s",
		"done_creds":         "  Administrator: %s  password: %s  (shown once — store it safely)",
		"done_log":           "  Log: %s",
		"done_reboot":        "  ! A reboot is required to activate disk quotas.",
		"done_warnings":      "Warnings:",
		"next_steps":         "Next steps: point your nameservers/A records here, set the contact email, check that port 25 and reverse DNS (PTR) are allowed by your provider.",
	},
	"tr": {
		"banner":             "BOZKURT PANEL %s kurucusu — %s — profil: %s",
		"stage_start":        "[%d/%d] %s …",
		"stage_skip":         "[%d/%d] %s — zaten tamamlandı, atlanıyor",
		"stage_ok":           "  ✔ %s (%s)",
		"stage_fail":         "  ✘ %s başarısız: %v",
		"resume_hint":        "Sorunu giderip kurucuyu yeniden çalıştırın; bu aşamadan devam eder. Ayrıntılı günlük: %s",
		"stage.preflight":    "Ön kontroller",
		"stage.repos":        "Paket depoları",
		"stage.packages":     "Paketler",
		"stage.system":       "Sistem hazırlığı (kullanıcılar, kota, sınırlar)",
		"stage.configs":      "Servis yapılandırması",
		"stage.panel":        "Panel servisleri",
		"stage.hostname-ssl": "Sunucu adı sertifikası",
		"stage.selftest":     "Kendi kendine test",
		"stage.upgrade":      "Yükseltme (paketler, sıkılaştırma, panel, geçişler)",
		"not_root":           "kurucu root olarak çalıştırılmalı",
		"apt_wait":           "  … başka bir paket yöneticisinin bitmesi bekleniyor (%s kilitli)",
		"unsupported":        "%s desteklenen bir sistem değil (Ubuntu 24.04, AlmaLinux 9); yine de denemek için --allow-unsupported kullanın",
		"not_fresh":          "bu sunucu temiz değil: %s (riski üstlenerek devam etmek için --force)",
		"requirements":       "bu sunucu asgari gereksinimleri karşılamıyor: %s",
		"upgrade_start":      "BOZKURT PANEL %s → %s sürümüne yükseltiliyor (profil %s); web siteleri, posta ve veriler çalışmaya devam eder",
		"upgrade_current":    "BOZKURT PANEL %s zaten kurulu ve güncel; yapılandırma yeniden uygulanıyor (tekrar çalıştırmak güvenlidir)",
		"upgrade_done":       "✔ BOZKURT PANEL %s sürümüne yükseltildi",
		"upgrade_none":       "Bu sunucuda BOZKURT PANEL kurulu değil (%s içinde tamamlanmış kurulum yok); önce install çalıştırın",
		"upgrade_newer":      "kurulu sürüm %s bu kurucudan (%s) daha yeni; sürüm düşürme yapılmaz",
		"done_title":         "✔ BOZKURT PANEL %s kuruldu",
		"done_user":          "  Kullanıcı paneli : https://%s:2083/   (HTTP 2082 yönlendirir)",
		"done_admin":         "  Yönetici paneli  : https://%s:2087/   (HTTP 2086 yönlendirir)",
		"done_webmail":       "  Web posta        : https://%s:2096/   (HTTP 2095 yönlendirir)",
		"done_login":         "  Tek kullanımlık giriş bağlantısı (15 dk): %s",
		"done_creds":         "  Yönetici: %s  parola: %s  (yalnızca bir kez gösterilir — güvenle saklayın)",
		"done_log":           "  Günlük: %s",
		"done_reboot":        "  ! Disk kotalarının etkinleşmesi için yeniden başlatma gerekiyor.",
		"done_warnings":      "Uyarılar:",
		"next_steps":         "Sonraki adımlar: ad sunucularınızı/A kayıtlarınızı buraya yönlendirin, iletişim e-postasını ayarlayın, sağlayıcınızın 25 numaralı porta ve ters DNS (PTR) kaydına izin verdiğini kontrol edin.",
	},
}

// T returns the message for key in lang, falling back to English.
func T(lang, key string) string {
	if m, ok := messages[lang]; ok {
		if s, ok := m[key]; ok {
			return s
		}
	}
	if s, ok := messages["en"][key]; ok {
		return s
	}
	return key
}
