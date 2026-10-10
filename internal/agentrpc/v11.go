// SPDX-License-Identifier: Apache-2.0

package agentrpc

// v1.1 feature-parity methods: visitor statistics, Leech Protection, email
// routing, mail queue / troubleshooter, CalDAV/CardDAV (Radicale), GnuPG,
// SSH keys, hostname, IP functions and PHP extensions.
const (
	MLogStats        = "logs.stats"         // user: Awstats/Visitors-style summary of one own domain log
	MWebxLeechScan   = "webx.leech_scan"    // user: distinct client IPs per basic-auth login below protected dirs
	MMailRoutingSet  = "mail.routing.set"   // user: local | remote | backup routing of one own mail domain
	MMailQueueList   = "mail.queue.list"    // server: postqueue -j
	MMailQueueAction = "mail.queue.action"  // server: postsuper / postqueue on queue ids
	MMailQueueShow   = "mail.queue.show"    // server: postcat -q <id> (bounded)
	MMailTrace       = "mail.trace"         // server: Postfix map lookups for one address (troubleshooter)
	MDavSync         = "dav.sync"           // user: replace the account's CalDAV/CardDAV logins
	MDavStatus       = "dav.status"         // server: Radicale presence and state
	MGPGList         = "gpg.list"           // user: keys of the account keyring
	MGPGGenerate     = "gpg.generate"       // user: new key pair
	MGPGImport       = "gpg.import"         // user: import an armored key
	MGPGDelete       = "gpg.delete"         // user: delete a key (and its secret part)
	MGPGExport       = "gpg.export"         // user: armored public key
	MSSHKeyList      = "ssh.keys.list"      // user: ~/.ssh keys and authorized_keys
	MSSHKeyImport    = "ssh.keys.import"    // user: store a public (and optional private) key
	MSSHKeyGenerate  = "ssh.keys.generate"  // user: new ed25519 / RSA key pair
	MSSHKeyAuthorize = "ssh.keys.authorize" // user: add / remove a key from authorized_keys
	MSSHKeyDelete    = "ssh.keys.delete"    // user: delete key files (and authorization)
	MSysHostname     = "system.hostname"    // server: change the server hostname
	MNetIPs          = "net.ips"            // server: interfaces and addresses
	MNetIPAdd        = "net.ip.add"         // server: add an address (persisted by bpanel-ips.service)
	MNetIPRemove     = "net.ip.remove"      // server: remove a panel-added address
	MPHPExtList      = "php.ext.list"       // server: allowlisted extensions of one PHP version
	MPHPExtSet       = "php.ext.set"        // server: install / remove one extension package
)

// ---- statistics -------------------------------------------------------------

type LogStatsParams struct {
	User     string `json:"user"`
	Domain   string `json:"domain"`
	MaxBytes int64  `json:"max_bytes,omitempty"` // tail of the log to read; 0 = 32 MiB
}

type LogCount struct {
	Key string `json:"key"`
	N   int64  `json:"n"`
}

type LogDay struct {
	Day      string `json:"day"`
	Hits     int64  `json:"hits"`
	Pages    int64  `json:"pages"`
	Visitors int64  `json:"visitors"` // distinct client IPs
	Bytes    int64  `json:"bytes"`
}

type LogHit struct {
	Time     int64  `json:"time"`
	IP       string `json:"ip"`
	Method   string `json:"method"`
	Path     string `json:"path"`
	Status   int    `json:"status"`
	Bytes    int64  `json:"bytes"`
	Referrer string `json:"referrer,omitempty"`
	Agent    string `json:"agent,omitempty"`
}

type LogStatsResult struct {
	Status    string     `json:"status"` // ok | no_log
	Reason    string     `json:"reason,omitempty"`
	Lines     int64      `json:"lines"`
	Skipped   int64      `json:"skipped"`
	Truncated bool       `json:"truncated"` // only the tail of the log was read
	Days      []LogDay   `json:"days"`
	Pages     []LogCount `json:"pages"`
	Referrers []LogCount `json:"referrers"`
	Browsers  []LogCount `json:"browsers"`
	Systems   []LogCount `json:"systems"`
	Codes     []LogCount `json:"codes"`
	Hosts     []LogCount `json:"hosts"`
	Recent    []LogHit   `json:"recent"`
}

type LeechScanParams struct {
	User   string   `json:"user"`
	Domain string   `json:"domain"`
	Paths  []string `json:"paths"`  // protected URL paths ("/dir/")
	Window int64    `json:"window"` // seconds to look back
}

type LeechHit struct {
	Path  string `json:"path"`
	Login string `json:"login"`
	IPs   int    `json:"ips"`
}

type LeechScanResult struct {
	Status string     `json:"status"` // ok | no_log
	Hits   []LeechHit `json:"hits"`
}

// ---- mail -------------------------------------------------------------------

type MailRoutingParams struct {
	User   string `json:"user"`
	Domain string `json:"domain"`
	Mode   string `json:"mode"` // local | remote | backup
}

type MailRoutingResult struct {
	Status string `json:"status"` // applied | not_installed
	Reason string `json:"reason,omitempty"`
}

type QueueRcpt struct {
	Address string `json:"address"`
	Reason  string `json:"reason,omitempty"`
}

type QueueMsg struct {
	ID         string      `json:"id"`
	Queue      string      `json:"queue"` // active | deferred | hold | incoming | maildrop
	Sender     string      `json:"sender"`
	Recipients []QueueRcpt `json:"recipients"`
	Size       int64       `json:"size"`
	Arrival    int64       `json:"arrival"`
}

type MailQueueListParams struct {
	Limit int `json:"limit,omitempty"` // 0 = 1000
}

type MailQueueListResult struct {
	Status   string     `json:"status"` // ok | not_installed
	Reason   string     `json:"reason,omitempty"`
	Total    int        `json:"total"`
	Messages []QueueMsg `json:"messages"`
}

type MailQueueActionParams struct {
	Action string   `json:"action"` // delete | hold | release | requeue | flush | deliver
	IDs    []string `json:"ids,omitempty"`
	All    bool     `json:"all,omitempty"`
}

type MailQueueActionResult struct {
	Status   string `json:"status"`
	Affected int    `json:"affected"`
	Output   string `json:"output,omitempty"`
}

type MailQueueShowParams struct {
	ID string `json:"id"`
}

type MailQueueShowResult struct {
	Status    string `json:"status"`
	Text      string `json:"text"`
	Truncated bool   `json:"truncated"`
}

type MailTraceParams struct {
	Address string `json:"address"`
}

type TraceStep struct {
	Check  string `json:"check"`
	Result string `json:"result"` // pass | fail | info | skip
	Detail string `json:"detail,omitempty"`
}

type MailTraceResult struct {
	Status string      `json:"status"` // ok | not_installed
	Reason string      `json:"reason,omitempty"`
	Steps  []TraceStep `json:"steps"`
}

// ---- calendars & contacts ------------------------------------------------------

// DavLogin is one CalDAV/CardDAV login (an own mailbox address) with a
// bcrypt hash of its DAV password.
type DavLogin struct {
	Name string `json:"name"`
	Hash string `json:"hash"`
}

type DavSyncParams struct {
	User   string     `json:"user"`
	Logins []DavLogin `json:"logins"`
}

type DavStatusResult struct {
	Status string `json:"status"` // active | inactive | not_installed
	Reason string `json:"reason,omitempty"`
	Users  int    `json:"users"`
}

// ---- GnuPG ---------------------------------------------------------------------

type GPGKey struct {
	Fingerprint string   `json:"fingerprint"`
	KeyID       string   `json:"key_id"`
	Algo        string   `json:"algo"`
	Bits        int      `json:"bits"`
	Created     int64    `json:"created"`
	Expires     int64    `json:"expires,omitempty"`
	UIDs        []string `json:"uids"`
	Secret      bool     `json:"secret"`
}

type GPGListParams struct {
	User string `json:"user"`
}

type GPGListResult struct {
	Status string   `json:"status"` // ok | not_installed
	Reason string   `json:"reason,omitempty"`
	Keys   []GPGKey `json:"keys"`
}

type GPGGenerateParams struct {
	User       string `json:"user"`
	Name       string `json:"name"`
	Email      string `json:"email"`
	Comment    string `json:"comment,omitempty"`
	Algo       string `json:"algo"`   // ed25519 | rsa3072 | rsa4096
	Expire     string `json:"expire"` // 0 | 1y | 2y | 5y
	Passphrase string `json:"passphrase,omitempty"`
}

type GPGImportParams struct {
	User    string `json:"user"`
	Armored string `json:"armored"`
}

type GPGKeyRef struct {
	User        string `json:"user"`
	Fingerprint string `json:"fingerprint"`
}

type GPGOutput struct {
	Status  string `json:"status"`
	Output  string `json:"output,omitempty"`
	Armored string `json:"armored,omitempty"`
}

// ---- SSH keys ------------------------------------------------------------------

type SSHKey struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Bits        int    `json:"bits,omitempty"`
	Fingerprint string `json:"fingerprint"`
	Comment     string `json:"comment,omitempty"`
	Authorized  bool   `json:"authorized"`
	HasPrivate  bool   `json:"has_private"`
	PublicKey   string `json:"public_key"`
}

type SSHKeyListParams struct {
	User string `json:"user"`
}

type SSHKeyListResult struct {
	Keys []SSHKey `json:"keys"`
}

type SSHKeyImportParams struct {
	User       string `json:"user"`
	Name       string `json:"name"`
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key,omitempty"`
	Authorize  bool   `json:"authorize"`
}

type SSHKeyGenerateParams struct {
	User       string `json:"user"`
	Name       string `json:"name"`
	Type       string `json:"type"` // ed25519 | rsa
	Bits       int    `json:"bits,omitempty"`
	Passphrase string `json:"passphrase,omitempty"`
	Authorize  bool   `json:"authorize"`
}

type SSHKeyGenerateResult struct {
	Key        SSHKey `json:"key"`
	PrivateKey string `json:"private_key"` // shown once (also stored in ~/.ssh/<name>)
}

type SSHKeyRef struct {
	User      string `json:"user"`
	Name      string `json:"name"`
	Authorize bool   `json:"authorize,omitempty"`
}

// ---- server: hostname, IPs, PHP extensions ------------------------------------

type SysHostnameParams struct {
	Hostname string `json:"hostname"`
}

type SysHostnameResult struct {
	Previous string   `json:"previous"`
	Hostname string   `json:"hostname"`
	Steps    []string `json:"steps"`
}

type NetAddr struct {
	IP      string `json:"ip"`
	Prefix  int    `json:"prefix"`
	Family  string `json:"family"` // ipv4 | ipv6
	Scope   string `json:"scope"`  // global | link | loopback | private
	Managed bool   `json:"managed"`
}

type NetIface struct {
	Name  string    `json:"name"`
	Up    bool      `json:"up"`
	MAC   string    `json:"mac,omitempty"`
	Addrs []NetAddr `json:"addrs"`
}

type NetIPsResult struct {
	Interfaces []NetIface `json:"interfaces"`
}

type NetIPParams struct {
	IP     string `json:"ip"`
	Prefix int    `json:"prefix"`
	Dev    string `json:"dev"`
}

type PHPExtListParams struct {
	Version string `json:"version"`
}

type PHPExt struct {
	Name      string `json:"name"`
	Package   string `json:"package"`
	Installed bool   `json:"installed"`
	Builtin   bool   `json:"builtin,omitempty"`
}

type PHPExtListResult struct {
	Status     string   `json:"status"` // ok | not_installed
	Reason     string   `json:"reason,omitempty"`
	Manager    string   `json:"manager"`
	Extensions []PHPExt `json:"extensions"`
}

type PHPExtSetParams struct {
	Version string `json:"version"`
	Ext     string `json:"ext"`
	Install bool   `json:"install"`
}

type PHPExtSetResult struct {
	Status string `json:"status"`
	Output string `json:"output,omitempty"`
}
