// SPDX-License-Identifier: Apache-2.0

package agentrpc

// v0.4 dbx: remote MySQL hosts, per-user connection limits, process list /
// kill of own queries, optional PostgreSQL engine (spec §13).

const (
	MDBXRemoteSync  = "dbx.remote.sync" // mirror every <owner>_ MariaDB user to the allowed remote hosts
	MDBXProcessList = "dbx.processlist" // running queries of the owner's DB users (MariaDB + PostgreSQL)
	MDBXKill        = "dbx.kill"        // cancel one running query of the owner
	MPGStatus       = "pg.status"       // PostgreSQL presence/version (server-level)
	MPGCreate       = "pg.create"       // database + login role (same name), least privilege
	MPGDrop         = "pg.drop"
	MPGPassword     = "pg.password"
	MPGLimit        = "pg.limit" // CONNECTION LIMIT of the owner's roles
	MPGSizes        = "pg.sizes"
)

type DBXGrant struct {
	DB         string   `json:"db"`
	Privileges []string `json:"privileges"`
}

type DBXRemoteUser struct {
	User   string     `json:"user"`
	Grants []DBXGrant `json:"grants"`
}

// DBXRemoteSync is the complete desired state of one account: the agent
// creates 'user'@'host' for every user x allowed host (same password hash
// and grants as 'user'@'localhost'), drops remote accounts of <owner>_ users
// on hosts no longer allowed, and sets MAX_USER_CONNECTIONS on all of them.
type DBXRemoteSync struct {
	Owner   string          `json:"owner"`
	Hosts   []string        `json:"hosts"` // as entered (IP, IPv4 CIDR, hostname); re-validated by the agent
	Users   []DBXRemoteUser `json:"users"`
	MaxConn int             `json:"max_conn"` // 0 = unlimited
}

type DBXRemoteResult struct {
	Created []string `json:"created"`
	Dropped []string `json:"dropped"`
	Skipped []string `json:"skipped"` // users without a local account (nothing to mirror)
}

type DBXProcReq struct {
	Owner string `json:"owner"`
}

type DBXProcess struct {
	Engine  string `json:"engine"` // mariadb | postgresql
	ID      int64  `json:"id"`
	User    string `json:"user"`
	Host    string `json:"host"`
	DB      string `json:"db"`
	Command string `json:"command"`
	State   string `json:"state"`
	Seconds int64  `json:"seconds"`
	Query   string `json:"query"`
}

type DBXEngineStatus struct {
	Status string `json:"status"` // ok | not_installed | unreachable
	Reason string `json:"reason,omitempty"`
}

type DBXProcList struct {
	Processes  []DBXProcess    `json:"processes"`
	MariaDB    DBXEngineStatus `json:"mariadb"`
	PostgreSQL DBXEngineStatus `json:"postgresql"`
}

type DBXKill struct {
	Owner  string `json:"owner"`
	Engine string `json:"engine"`
	ID     int64  `json:"id"`
}

type PGStatus struct {
	Status  string `json:"status"` // ok | not_installed | unreachable
	Version string `json:"version,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

// PGDB names one database; its login role has the same name.
type PGDB struct {
	Owner    string `json:"owner"`
	Name     string `json:"name"`
	Password string `json:"password,omitempty"` // create / password only; hashed to SCRAM by the agent
	MaxConn  int    `json:"max_conn,omitempty"` // 0 = unlimited
}

type PGLimit struct {
	Owner   string   `json:"owner"`
	Names   []string `json:"names"`
	MaxConn int      `json:"max_conn"`
}

type PGSizesReq struct {
	Owner string `json:"owner"`
}
