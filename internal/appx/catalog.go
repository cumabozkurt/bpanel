// SPDX-License-Identifier: Apache-2.0

package appx

// Catalogue of free, open-source web applications. Every enabled entry has a
// pinned version and a checksum taken from the project's own published
// value (verified 2026-10-10 against the download itself):
//   WordPress 7.1.3  sha1 published at https://wordpress.org/wordpress-7.1.3.tar.gz.sha1
//   Joomla 6.1.4     sha256 published in the GitHub release notes of joomla/joomla-cms 6.1.4
//   Drupal 11.4.9    md5 published in https://updates.drupal.org/release-history/drupal/current
//                    (sha256 below computed from the same file after the md5 matched)
//   Nextcloud 35.0.1 sha256 published at https://download.nextcloud.com/server/releases/nextcloud-35.0.1.tar.bz2.sha256
// Added in v1.2.0 (verified 2026-10-11, each file downloaded and hashed here):
//   Matomo 5.14.1     sha256 = GitHub release asset digest; GPG signature (.asc) verified with
//                     the Matomo key F529A27008477483777FC23D63BB30D0E5D2C749
//   phpBB 3.3.19      sha256 published at https://download.phpbb.com/pub/release/3.3/3.3.19/phpBB-3.3.19.tar.bz2.sha256
//   MediaWiki 1.46.2  GPG signature (.sig) verified with https://www.mediawiki.org/keys/keys.txt
//                     (key 1D98867E82982C8FE0ABC25F9B69B3109D3BB7B0); sha256 computed from that file
//   Grav 2.2.6, DokuWiki 2026-07-14c, Backdrop CMS 1.35.1, OpenCart 4.1.0.4,
//   MyBB 1.8.41, Mautic 7.2.1, WonderCMS 3.6.0, Omeka S 4.2.1, FOSSBilling 0.8.8
//                     sha256 = digest GitHub publishes for the release asset
//                     (api.github.com/repos/<project>/releases), matched by the download
// The agent only ever downloads URLs from this table (never a URL from the
// API) and refuses any file whose hash differs. An entry whose checksum
// could not be confirmed is listed with Enabled=false and a reason.

type CatalogApp struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Version     string      `json:"version"`
	License     string      `json:"license"`
	Homepage    string      `json:"homepage"`
	URL         string      `json:"-"`
	SHA256      string      `json:"sha256,omitempty"`
	SHA1        string      `json:"sha1,omitempty"`
	Category    string      `json:"category"`  // cms | blog | wiki | forum | shop | analytics | marketing | files
	Format      string      `json:"format"`    // tar.gz | tar.bz2 | zip
	Strip       string      `json:"-"`         // top-level directory inside the archive ("" = none)
	StripOnly   bool        `json:"-"`         // skip (instead of refuse) entries outside Strip/ (READMEs next to the app dir)
	RootOnly    bool        `json:"root_only"` // the app's .htaccess assumes the document root (RewriteBase /, ^/index.php): no sub-directory installs
	Renames     [][2]string `json:"-"`         // after extraction: from -> to, inside the install directory (config-dist.php -> config.php)
	NeedsDB     bool        `json:"needs_db"`
	MinPHP      string      `json:"min_php"`
	Enabled     bool        `json:"enabled"`
	Disabled    string      `json:"disabled_reason,omitempty"`
	PostInstall string      `json:"post_install"` // what the user finishes in the browser
}

var Catalog = []CatalogApp{
	{ID: "wordpress", Name: "WordPress", Version: "7.1.3", License: "GPL-2.0-or-later", Homepage: "https://wordpress.org", Category: "cms",
		URL:    "https://wordpress.org/wordpress-7.1.3.tar.gz",
		SHA1:   "491a78c7676b15dffcc69130c6054b8f49228a91",
		SHA256: "d2a09acb6a15e3b9c471d72557753c266d6f41a79ed19bfe04cbfe49e283b2a5",
		Format: "tar.gz", Strip: "wordpress", NeedsDB: true, MinPHP: "7.4", Enabled: true,
		PostInstall: "wp-config.php is written for you; open the site to pick the title and the admin user"},
	{ID: "joomla", Name: "Joomla!", Version: "6.1.4", License: "GPL-2.0-or-later", Homepage: "https://www.joomla.org", Category: "cms",
		URL:    "https://github.com/joomla/joomla-cms/releases/download/6.1.4/Joomla_6.1.4-Stable-Full_Package.tar.gz",
		SHA256: "9558a3a3754cbe798c8a8b3d46afa4e4a0a9284de876e4ce82c0ccaeb9f4af41",
		Format: "tar.gz", Strip: "", NeedsDB: true, MinPHP: "8.3", Enabled: true,
		PostInstall: "open the site and finish the Joomla web installer with the database shown here"},
	{ID: "drupal", Name: "Drupal", Version: "11.4.9", License: "GPL-2.0-or-later", Homepage: "https://www.drupal.org", Category: "cms",
		URL:    "https://ftp.drupal.org/files/projects/drupal-11.4.9.tar.gz",
		SHA256: "198c0965f95e90b33da3d988ef28061a6ff95ec8c09c0c306424be71622ad104",
		Format: "tar.gz", Strip: "drupal-11.4.9", NeedsDB: true, MinPHP: "8.3", Enabled: true,
		PostInstall: "open the site and finish the Drupal installer with the database shown here"},
	{ID: "nextcloud", Name: "Nextcloud", Version: "35.0.1", License: "AGPL-3.0-or-later", Homepage: "https://nextcloud.com", Category: "files",
		URL:    "https://download.nextcloud.com/server/releases/nextcloud-35.0.1.tar.bz2",
		SHA256: "7ed305e880192d804ba83179a19dd22257679608d63161a611ce3f8a918d2aa6",
		Format: "tar.bz2", Strip: "nextcloud", NeedsDB: true, MinPHP: "8.2", Enabled: true,
		PostInstall: "open the site and finish the Nextcloud installer with the database shown here"},
	{ID: "matomo", Name: "Matomo", Version: "5.14.1", License: "GPL-3.0-or-later", Homepage: "https://matomo.org", Category: "analytics",
		URL:    "https://github.com/matomo-org/matomo/releases/download/5.14.1/matomo-5.14.1.tar.gz",
		SHA256: "6e2938c9a482fa715a02cacacc490f2e7d6fb1f4068e45de41181089c129080e",
		Format: "tar.gz", Strip: "matomo", StripOnly: true, NeedsDB: true, MinPHP: "7.2", Enabled: true,
		PostInstall: "open the site and finish the Matomo installer with the database shown here, then add the tracking code to your sites"},
	{ID: "phpbb", Name: "phpBB", Version: "3.3.19", License: "GPL-2.0-only", Homepage: "https://www.phpbb.com", Category: "forum",
		URL:    "https://download.phpbb.com/pub/release/3.3/3.3.19/phpBB-3.3.19.tar.bz2",
		SHA256: "66f35fa3d9bf3b90269205bbb281e1156727a0014eea344fe15f9c7376b78c66",
		Format: "tar.bz2", Strip: "phpBB3", NeedsDB: true, MinPHP: "7.2", Enabled: true,
		PostInstall: "open /install/ on the site, finish the phpBB installer with the database shown here, then delete the install directory"},
	{ID: "mediawiki", Name: "MediaWiki", Version: "1.46.2", License: "GPL-2.0-or-later", Homepage: "https://www.mediawiki.org", Category: "wiki",
		URL:    "https://releases.wikimedia.org/mediawiki/1.46/mediawiki-1.46.2.tar.gz",
		SHA256: "8f7f937f8bbc1acd4cef1c5362a95f248dcd242020f2588798eb2f73ac2e69ba",
		Format: "tar.gz", Strip: "mediawiki-1.46.2", NeedsDB: true, MinPHP: "8.3", Enabled: true,
		PostInstall: "open the site, run the MediaWiki setup with the database shown here and upload the generated LocalSettings.php with the File Manager"},
	{ID: "dokuwiki", Name: "DokuWiki", Version: "2026-07-14c", License: "GPL-2.0-only", Homepage: "https://www.dokuwiki.org", Category: "wiki",
		URL:    "https://github.com/dokuwiki/dokuwiki/releases/download/release-2026-07-14c/dokuwiki-2026-07-14c.tgz",
		SHA256: "7e9b4dcb5ecb91a57f71b9b77dcec7bcf929959881464796611349ed1d183176",
		Format: "tar.gz", Strip: "dokuwiki-2026-07-14c", NeedsDB: false, MinPHP: "8.2", Enabled: true,
		PostInstall: "open /install.php on the site to create the admin user, then delete install.php (DokuWiki needs no database)"},
	{ID: "grav", Name: "Grav (+Admin)", Version: "2.2.6", License: "MIT", Homepage: "https://getgrav.org", Category: "cms",
		URL:    "https://github.com/getgrav/grav/releases/download/2.2.6/grav-admin-v2.2.6.zip",
		SHA256: "81aae991738adebbb3da3383a23bf865e644c690fdfd0c0e368c09f9e3de1a1c",
		Format: "zip", Strip: "grav-admin", NeedsDB: false, MinPHP: "8.3", Enabled: true,
		PostInstall: "open /admin on the site to create the first administrator (Grav is flat-file: no database)"},
	{ID: "backdrop", Name: "Backdrop CMS", Version: "1.35.1", License: "GPL-2.0-or-later", Homepage: "https://backdropcms.org", Category: "cms",
		URL:    "https://github.com/backdrop/backdrop/releases/download/1.35.1/backdrop.zip",
		SHA256: "7add8d49fdbfee6819cfb4866cd3501f5e06df8000e39652ecf896a2fa7a729c",
		Format: "zip", Strip: "backdrop", NeedsDB: true, MinPHP: "7.1", Enabled: true,
		PostInstall: "open the site and finish the Backdrop installer with the database shown here"},
	{ID: "wondercms", Name: "WonderCMS", Version: "3.6.0", License: "MIT", Homepage: "https://www.wondercms.com", Category: "cms",
		URL:    "https://github.com/WonderCMS/wondercms/releases/download/3.6.0/wondercms-360.zip",
		SHA256: "14985f23f6a0766d251b48cda54579a1188ea56226c340059efd6c552ade9382",
		Format: "zip", Strip: "wondercms", NeedsDB: false, MinPHP: "7.4", Enabled: true,
		PostInstall: "open the site: the login password is shown once on the first page, change it right away (flat-file, no database)"},
	{ID: "mybb", Name: "MyBB", Version: "1.8.41", License: "LGPL-3.0-only", Homepage: "https://mybb.com", Category: "forum",
		URL:    "https://github.com/mybb/mybb/releases/download/mybb_1841/mybb_1841.zip",
		SHA256: "48cc76e9e1146ea052756575991f43f51a634f125eea06d05ce9041b03eedeaa",
		Format: "zip", Strip: "Upload", StripOnly: true, NeedsDB: true, MinPHP: "7.4", Enabled: true,
		PostInstall: "open /install/ on the site, finish the MyBB installer with the database shown here, then delete the install directory"},
	{ID: "opencart", Name: "OpenCart", Version: "4.1.0.4", License: "GPL-3.0-only", Homepage: "https://www.opencart.com", Category: "shop",
		URL:    "https://github.com/opencart/opencart/releases/download/4.1.0.4/opencart-4.1.0.4.zip",
		SHA256: "cdef537f5a0a7e1b4ddbe16f589dd2e80b10150a09bfbe93ce76ef2d5c3218c0",
		Format: "zip", Strip: "upload", StripOnly: true, NeedsDB: true, MinPHP: "8.1", Enabled: true,
		Renames:     [][2]string{{"config-dist.php", "config.php"}, {"admin/config-dist.php", "admin/config.php"}},
		PostInstall: "open /install/ on the site and finish the OpenCart installer with the database shown here"},
	{ID: "mautic", Name: "Mautic", Version: "7.2.1", License: "GPL-3.0-or-later", Homepage: "https://www.mautic.org", Category: "marketing",
		URL:    "https://github.com/mautic/mautic/releases/download/7.2.1/7.2.1.zip",
		SHA256: "5c86cf1fe8b4f9818232ce8bb755760f502d47846706e9164d144865d031ecbd",
		Format: "zip", Strip: "", NeedsDB: true, MinPHP: "8.2", Enabled: true, RootOnly: true,
		PostInstall: "open the site and finish the Mautic installer with the database shown here; add the Mautic cron jobs in Cron Jobs"},
	{ID: "omekas", Name: "Omeka S", Version: "4.2.1", License: "GPL-3.0-or-later", Homepage: "https://omeka.org/s/", Category: "cms",
		URL:    "https://github.com/omeka/omeka-s/releases/download/v4.2.1/omeka-s-4.2.1.zip",
		SHA256: "cc27d1c7aca0209523d19aa285f4a08e29e34950dcc446951a7c1311de348e82",
		Format: "zip", Strip: "omeka-s", NeedsDB: true, MinPHP: "8.1", Enabled: true,
		PostInstall: "edit config/database.ini in the File Manager with the database shown here, then open the site to create the administrator"},
	{ID: "fossbilling", Name: "FOSSBilling", Version: "0.8.8", License: "Apache-2.0", Homepage: "https://fossbilling.org", Category: "shop",
		URL:    "https://github.com/FOSSBilling/FOSSBilling/releases/download/0.8.8/FOSSBilling-0.8.8.zip",
		SHA256: "6ab8cb04ad8ace31622caa1d999dbc3b1ffd89143bcd650986d1302830fb08a5",
		Format: "zip", Strip: "", NeedsDB: true, MinPHP: "8.3", Enabled: true, RootOnly: true,
		PostInstall: "open /install/install.php on the site, finish the FOSSBilling installer with the database shown here and add its cron job in Cron Jobs"},
}

// Find returns the catalogue entry (enabled or not).
func Find(id string) (CatalogApp, bool) {
	for _, c := range Catalog {
		if c.ID == id {
			return c, true
		}
	}
	return CatalogApp{}, false
}
