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
// The agent only ever downloads URLs from this table (never a URL from the
// API) and refuses any file whose hash differs. An entry whose checksum
// could not be confirmed is listed with Enabled=false and a reason.

type CatalogApp struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	License     string `json:"license"`
	Homepage    string `json:"homepage"`
	URL         string `json:"-"`
	SHA256      string `json:"sha256,omitempty"`
	SHA1        string `json:"sha1,omitempty"`
	Format      string `json:"-"` // tar.gz | tar.bz2
	Strip       string `json:"-"` // top-level directory inside the archive ("" = none)
	NeedsDB     bool   `json:"needs_db"`
	MinPHP      string `json:"min_php"`
	Enabled     bool   `json:"enabled"`
	Disabled    string `json:"disabled_reason,omitempty"`
	PostInstall string `json:"post_install"` // what the user finishes in the browser
}

var Catalog = []CatalogApp{
	{ID: "wordpress", Name: "WordPress", Version: "7.1.3", License: "GPL-2.0-or-later", Homepage: "https://wordpress.org",
		URL:    "https://wordpress.org/wordpress-7.1.3.tar.gz",
		SHA1:   "491a78c7676b15dffcc69130c6054b8f49228a91",
		SHA256: "d2a09acb6a15e3b9c471d72557753c266d6f41a79ed19bfe04cbfe49e283b2a5",
		Format: "tar.gz", Strip: "wordpress", NeedsDB: true, MinPHP: "7.4", Enabled: true,
		PostInstall: "wp-config.php is written for you; open the site to pick the title and the admin user"},
	{ID: "joomla", Name: "Joomla!", Version: "6.1.4", License: "GPL-2.0-or-later", Homepage: "https://www.joomla.org",
		URL:    "https://github.com/joomla/joomla-cms/releases/download/6.1.4/Joomla_6.1.4-Stable-Full_Package.tar.gz",
		SHA256: "9558a3a3754cbe798c8a8b3d46afa4e4a0a9284de876e4ce82c0ccaeb9f4af41",
		Format: "tar.gz", Strip: "", NeedsDB: true, MinPHP: "8.3", Enabled: true,
		PostInstall: "open the site and finish the Joomla web installer with the database shown here"},
	{ID: "drupal", Name: "Drupal", Version: "11.4.9", License: "GPL-2.0-or-later", Homepage: "https://www.drupal.org",
		URL:    "https://ftp.drupal.org/files/projects/drupal-11.4.9.tar.gz",
		SHA256: "198c0965f95e90b33da3d988ef28061a6ff95ec8c09c0c306424be71622ad104",
		Format: "tar.gz", Strip: "drupal-11.4.9", NeedsDB: true, MinPHP: "8.3", Enabled: true,
		PostInstall: "open the site and finish the Drupal installer with the database shown here"},
	{ID: "nextcloud", Name: "Nextcloud", Version: "35.0.1", License: "AGPL-3.0-or-later", Homepage: "https://nextcloud.com",
		URL:    "https://download.nextcloud.com/server/releases/nextcloud-35.0.1.tar.bz2",
		SHA256: "7ed305e880192d804ba83179a19dd22257679608d63161a611ce3f8a918d2aa6",
		Format: "tar.bz2", Strip: "nextcloud", NeedsDB: true, MinPHP: "8.2", Enabled: true,
		PostInstall: "open the site and finish the Nextcloud installer with the database shown here"},
	{ID: "matomo", Name: "Matomo", Version: "", License: "GPL-3.0-or-later", Homepage: "https://matomo.org",
		Enabled: false, Disabled: "no pinned release checksum confirmed yet"},
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
