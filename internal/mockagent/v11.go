//go:build dev

// SPDX-License-Identifier: Apache-2.0

package mockagent

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
	"github.com/cumabozkurt/bpanel/internal/distro"
)

// v1.1 methods: deterministic fake state for `bpanel-api --dev` screenshots
// and the web UI; nothing here touches the system.
var v11 = struct {
	sync.Mutex
	queue []rpc.QueueMsg
	gpg   map[string][]rpc.GPGKey
	ssh   map[string][]rpc.SSHKey
	ips   []rpc.NetAddr
	ext   map[string]bool
	dav   map[string]int
	host  string
}{gpg: map[string][]rpc.GPGKey{}, ssh: map[string][]rpc.SSHKey{}, ext: map[string]bool{"curl": true, "gd": true, "mbstring": true, "mysql": true, "xml": true, "zip": true, "intl": true, "opcache": true}, dav: map[string]int{}, host: "panel.example.com"}

// V11Methods are the v1.1 methods handled by MockV11.
var V11Methods = []string{rpc.MLogStats, rpc.MWebxLeechScan, rpc.MMailRoutingSet, rpc.MMailQueueList, rpc.MMailQueueAction,
	rpc.MMailQueueShow, rpc.MMailTrace, rpc.MDavSync, rpc.MDavStatus, rpc.MGPGList, rpc.MGPGGenerate, rpc.MGPGImport, rpc.MGPGDelete,
	rpc.MGPGExport, rpc.MSSHKeyList, rpc.MSSHKeyImport, rpc.MSSHKeyGenerate, rpc.MSSHKeyAuthorize, rpc.MSSHKeyDelete, rpc.MSysHostname,
	rpc.MNetIPs, rpc.MNetIPAdd, rpc.MNetIPRemove, rpc.MPHPExtList, rpc.MPHPExtSet}

func fakeFpr(s string) string {
	h := sha256.Sum256([]byte(s))
	return strings.ToUpper(hex.EncodeToString(h[:20]))
}

func (m *Mock) mockV11(method string, params any) (any, error) {
	v11.Lock()
	defer v11.Unlock()
	if v11.queue == nil {
		now := time.Now().Unix()
		v11.queue = []rpc.QueueMsg{
			{ID: "4F2A1C0B3D", Queue: "deferred", Sender: "wordpress@demo.test", Size: 4210, Arrival: now - 3600,
				Recipients: []rpc.QueueRcpt{{Address: "someone@gmail.com", Reason: "connect to gmail-smtp-in.l.google.com[142.250.0.27]:25: Connection timed out"}}},
			{ID: "7C3D9E1A2B", Queue: "hold", Sender: "newsletter@demo.test", Size: 18230, Arrival: now - 7200,
				Recipients: []rpc.QueueRcpt{{Address: "list@example.net"}}},
		}
		v11.ips = []rpc.NetAddr{{IP: "203.0.113.10", Prefix: 24, Family: "ipv4", Scope: "global"}, {IP: "2001:db8::10", Prefix: 64, Family: "ipv6", Scope: "global"}}
	}
	switch method {
	case rpc.MLogStats:
		var p rpc.LogStatsParams
		conv(params, &p)
		res := rpc.LogStatsResult{Status: "ok", Lines: 1840, Days: []rpc.LogDay{}}
		for i := 6; i >= 0; i-- {
			d := time.Now().AddDate(0, 0, -i).UTC().Format("2006-01-02")
			res.Days = append(res.Days, rpc.LogDay{Day: d, Hits: int64(180 + i*23), Pages: int64(60 + i*7), Visitors: int64(30 + i*5), Bytes: int64(4<<20 + i<<19)})
		}
		res.Pages = []rpc.LogCount{{Key: "/", N: 220}, {Key: "/blog/", N: 120}, {Key: "/contact.php", N: 41}}
		res.Referrers = []rpc.LogCount{{Key: "www.google.com", N: 90}, {Key: "duckduckgo.com", N: 12}}
		res.Browsers = []rpc.LogCount{{Key: "Chrome", N: 900}, {Key: "Safari", N: 400}, {Key: "Firefox", N: 210}, {Key: "Robot", N: 120}}
		res.Systems = []rpc.LogCount{{Key: "Windows", N: 700}, {Key: "Android", N: 500}, {Key: "iOS", N: 300}}
		res.Codes = []rpc.LogCount{{Key: "200", N: 1600}, {Key: "304", N: 140}, {Key: "404", N: 80}}
		res.Hosts = []rpc.LogCount{{Key: "203.0.113.7", N: 90}, {Key: "198.51.100.4", N: 40}}
		res.Recent = []rpc.LogHit{{Time: time.Now().Unix() - 30, IP: "203.0.113.7", Method: "GET", Path: "/", Status: 200, Bytes: 5120, Agent: "Mozilla/5.0 Chrome/129.0"}}
		return res, nil
	case rpc.MWebxLeechScan:
		return rpc.LeechScanResult{Status: "ok", Hits: []rpc.LeechHit{}}, nil
	case rpc.MMailRoutingSet:
		return rpc.MailRoutingResult{Status: "applied"}, nil
	case rpc.MMailQueueList:
		return rpc.MailQueueListResult{Status: "ok", Total: len(v11.queue), Messages: append([]rpc.QueueMsg{}, v11.queue...)}, nil
	case rpc.MMailQueueAction:
		var p rpc.MailQueueActionParams
		conv(params, &p)
		sel := map[string]bool{}
		for _, id := range p.IDs {
			sel[id] = true
		}
		n := 0
		keep := v11.queue[:0]
		for _, q := range v11.queue {
			hit := p.All || sel[q.ID]
			if hit {
				n++
			}
			switch {
			case hit && p.Action == "delete":
				continue
			case hit && p.Action == "hold":
				q.Queue = "hold"
			case hit && (p.Action == "release" || p.Action == "requeue"):
				q.Queue = "deferred"
			}
			keep = append(keep, q)
		}
		v11.queue = keep
		return rpc.MailQueueActionResult{Status: "ok", Affected: n}, nil
	case rpc.MMailQueueShow:
		var p rpc.MailQueueShowParams
		conv(params, &p)
		return rpc.MailQueueShowResult{Status: "ok", Text: "*** MESSAGE CONTENTS " + p.ID + " ***\nFrom: wordpress@demo.test\nSubject: New comment\n\nA new comment is waiting.\n"}, nil
	case rpc.MMailTrace:
		var p rpc.MailTraceParams
		conv(params, &p)
		dom := p.Address[strings.LastIndex(p.Address, "@")+1:]
		return rpc.MailTraceResult{Status: "ok", Steps: []rpc.TraceStep{
			{Check: "virtual_mailbox_domains", Result: "pass", Detail: dom + " is hosted here"},
			{Check: "virtual_mailbox_maps", Result: "pass", Detail: p.Address + " -> mailbox " + dom + "/"},
			{Check: "transport", Result: "pass", Detail: "delivered locally via lmtp:unix:private/dovecot-lmtp"}}}, nil
	case rpc.MDavSync:
		var p rpc.DavSyncParams
		conv(params, &p)
		v11.dav[p.User] = len(p.Logins)
		n := 0
		for _, c := range v11.dav {
			n += c
		}
		return rpc.DavStatusResult{Status: "active", Users: n}, nil
	case rpc.MDavStatus:
		n := 0
		for _, c := range v11.dav {
			n += c
		}
		return rpc.DavStatusResult{Status: "active", Users: n}, nil
	case rpc.MGPGList:
		var p rpc.GPGListParams
		conv(params, &p)
		return rpc.GPGListResult{Status: "ok", Keys: append([]rpc.GPGKey{}, v11.gpg[p.User]...)}, nil
	case rpc.MGPGGenerate:
		var p rpc.GPGGenerateParams
		conv(params, &p)
		f := fakeFpr(p.User + p.Email + p.Name)
		v11.gpg[p.User] = append(v11.gpg[p.User], rpc.GPGKey{Fingerprint: f, KeyID: f[24:], Algo: "EdDSA", Bits: 255, Created: time.Now().Unix(),
			UIDs: []string{p.Name + " <" + p.Email + ">"}, Secret: true})
		return rpc.GPGOutput{Status: "ok"}, nil
	case rpc.MGPGImport:
		var p rpc.GPGImportParams
		conv(params, &p)
		f := fakeFpr(p.Armored)
		v11.gpg[p.User] = append(v11.gpg[p.User], rpc.GPGKey{Fingerprint: f, KeyID: f[24:], Algo: "RSA", Bits: 3072, Created: time.Now().Unix(), UIDs: []string{"Imported key"}})
		return rpc.GPGOutput{Status: "ok"}, nil
	case rpc.MGPGDelete, rpc.MGPGExport:
		var p rpc.GPGKeyRef
		conv(params, &p)
		for i, k := range v11.gpg[p.User] {
			if k.Fingerprint == p.Fingerprint {
				if method == rpc.MGPGExport {
					return rpc.GPGOutput{Status: "ok", Armored: "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmDMEZ0mockmockmock\n-----END PGP PUBLIC KEY BLOCK-----\n"}, nil
				}
				v11.gpg[p.User] = append(v11.gpg[p.User][:i], v11.gpg[p.User][i+1:]...)
				return rpc.GPGOutput{Status: "ok"}, nil
			}
		}
		return nil, &rpc.Error{Code: "not_found", Message: p.Fingerprint}
	case rpc.MSSHKeyList:
		var p rpc.SSHKeyListParams
		conv(params, &p)
		ks := append([]rpc.SSHKey{}, v11.ssh[p.User]...)
		sort.Slice(ks, func(i, j int) bool { return ks[i].Name < ks[j].Name })
		return rpc.SSHKeyListResult{Keys: ks}, nil
	case rpc.MSSHKeyImport, rpc.MSSHKeyGenerate:
		var p rpc.SSHKeyGenerateParams
		conv(params, &p)
		var pub string
		if method == rpc.MSSHKeyImport {
			var ip rpc.SSHKeyImportParams
			conv(params, &ip)
			pub = ip.PublicKey
		}
		for _, k := range v11.ssh[p.User] {
			if k.Name == p.Name {
				return nil, &rpc.Error{Code: "ssh_key_exists", Message: p.Name}
			}
		}
		if pub == "" {
			pub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI" + fakeFpr(p.Name)[:43] + " " + p.User + "@bpanel"
		}
		k := rpc.SSHKey{Name: p.Name, Type: "ssh-ed25519", Fingerprint: "SHA256:" + fakeFpr(pub)[:43], Authorized: p.Authorize,
			HasPrivate: method == rpc.MSSHKeyGenerate, PublicKey: pub}
		v11.ssh[p.User] = append(v11.ssh[p.User], k)
		if method == rpc.MSSHKeyGenerate {
			return rpc.SSHKeyGenerateResult{Key: k, PrivateKey: "-----BEGIN OPENSSH PRIVATE KEY-----\nmock\n-----END OPENSSH PRIVATE KEY-----\n"}, nil
		}
		return k, nil
	case rpc.MSSHKeyAuthorize, rpc.MSSHKeyDelete:
		var p rpc.SSHKeyRef
		conv(params, &p)
		for i, k := range v11.ssh[p.User] {
			if k.Name == p.Name {
				if method == rpc.MSSHKeyDelete {
					v11.ssh[p.User] = append(v11.ssh[p.User][:i], v11.ssh[p.User][i+1:]...)
				} else {
					v11.ssh[p.User][i].Authorized = p.Authorize
				}
				return rpc.Empty{}, nil
			}
		}
		return nil, &rpc.Error{Code: "not_found", Message: p.Name}
	case rpc.MSysHostname:
		var p rpc.SysHostnameParams
		conv(params, &p)
		prev := v11.host
		v11.host = strings.ToLower(p.Hostname)
		return rpc.SysHostnameResult{Previous: prev, Hostname: v11.host, Steps: []string{"hostnamectl set-hostname (mock)"}}, nil
	case rpc.MNetIPs:
		return rpc.NetIPsResult{Interfaces: []rpc.NetIface{
			{Name: "lo", Up: true, Addrs: []rpc.NetAddr{{IP: "127.0.0.1", Prefix: 8, Family: "ipv4", Scope: "loopback"}}},
			{Name: "eth0", Up: true, MAC: "52:54:00:12:34:56", Addrs: append([]rpc.NetAddr{}, v11.ips...)}}}, nil
	case rpc.MNetIPAdd, rpc.MNetIPRemove:
		var p rpc.NetIPParams
		conv(params, &p)
		for i, a := range v11.ips {
			if a.IP == p.IP {
				if method == rpc.MNetIPAdd {
					return nil, &rpc.Error{Code: "ip_exists", Message: p.IP}
				}
				if !a.Managed {
					return nil, &rpc.Error{Code: "refused", Message: "only addresses added by the panel can be removed"}
				}
				v11.ips = append(v11.ips[:i], v11.ips[i+1:]...)
				return rpc.Empty{}, nil
			}
		}
		if method == rpc.MNetIPRemove {
			return nil, &rpc.Error{Code: "refused", Message: "unknown address"}
		}
		fam := "ipv4"
		if strings.Contains(p.IP, ":") {
			fam = "ipv6"
		}
		v11.ips = append(v11.ips, rpc.NetAddr{IP: p.IP, Prefix: p.Prefix, Family: fam, Scope: "global", Managed: true})
		return rpc.Empty{}, nil
	case rpc.MPHPExtList:
		var p rpc.PHPExtListParams
		conv(params, &p)
		res := rpc.PHPExtListResult{Status: "ok", Manager: "apt", Extensions: []rpc.PHPExt{}}
		for _, e := range distro.PHPExtensions {
			res.Extensions = append(res.Extensions, rpc.PHPExt{Name: e, Package: "php" + p.Version + "-" + e, Installed: v11.ext[p.Version+"/"+e] || v11.ext[e]})
		}
		return res, nil
	case rpc.MPHPExtSet:
		var p rpc.PHPExtSetParams
		conv(params, &p)
		v11.ext[p.Version+"/"+p.Ext] = p.Install
		if !p.Install {
			delete(v11.ext, p.Ext)
		}
		return rpc.PHPExtSetResult{Status: "ok", Output: fmt.Sprintf("mock: %v php%s-%s", map[bool]string{true: "installed", false: "removed"}[p.Install], p.Version, p.Ext)}, nil
	}
	return nil, &rpc.Error{Code: "unknown_method", Message: method}
}
