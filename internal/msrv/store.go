package msrv

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// TokenTTL is how long a join/rotate token stays valid.
const TokenTTL = 15 * time.Minute

var (
	ErrBadName    = errors.New("msrv_bad_name")
	ErrBadAddress = errors.New("msrv_bad_address")
	ErrNameTaken  = errors.New("msrv_name_taken")
)

var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,62}$`)

// Node is one msrv_nodes row.
type Node struct {
	ID           int64    `json:"id"`
	Name         string   `json:"name"`
	Address      string   `json:"address"`
	Roles        []string `json:"roles"`
	Status       string   `json:"status"`
	CertSerial   string   `json:"cert_serial"`
	CertNotAfter int64    `json:"cert_not_after"`
	CreatedAt    int64    `json:"created_at"`
	EnrolledAt   int64    `json:"enrolled_at"`
	LastSeen     int64    `json:"last_seen"`
	LastCheck    int64    `json:"last_check"`
	LatencyMS    int64    `json:"latency_ms"`
	Version      string   `json:"version"`
	Health       string   `json:"health"`
	HealthError  string   `json:"health_error,omitempty"`
}

// Store wraps the msrv tables.
type Store struct {
	DB  *sql.DB
	Now func() time.Time
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// HashToken is the stored form of a token.
func HashToken(tok string) string {
	h := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(h[:])
}

func newToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "bpj_" + base64.RawURLEncoding.EncodeToString(b), nil
}

// ValidAddress checks a host:port for the agent remote listener ("" allowed).
func ValidAddress(a string) bool {
	if a == "" {
		return true
	}
	h, p, err := net.SplitHostPort(a)
	if err != nil || h == "" || strings.ContainsAny(h, "/ \t") {
		return false
	}
	n, err := strconv.Atoi(p)
	return err == nil && n > 0 && n < 65536
}

const nodeCols = `id,name,address,roles,status,cert_serial,cert_not_after,created_at,enrolled_at,last_seen,last_check,latency_ms,version,health,health_error`

func scanNode(sc interface{ Scan(...any) error }) (*Node, error) {
	var n Node
	var roles string
	if err := sc.Scan(&n.ID, &n.Name, &n.Address, &roles, &n.Status, &n.CertSerial, &n.CertNotAfter, &n.CreatedAt,
		&n.EnrolledAt, &n.LastSeen, &n.LastCheck, &n.LatencyMS, &n.Version, &n.Health, &n.HealthError); err != nil {
		return nil, err
	}
	n.Roles = []string{}
	if roles != "" {
		n.Roles = strings.Split(roles, ",")
	}
	return &n, nil
}

// List returns every node.
func (s *Store) List(ctx context.Context) ([]Node, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT `+nodeCols+` FROM msrv_nodes ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Node{}
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *n)
	}
	return out, rows.Err()
}

// Get returns one node.
func (s *Store) Get(ctx context.Context, id int64) (*Node, error) {
	n, err := scanNode(s.DB.QueryRowContext(ctx, `SELECT `+nodeCols+` FROM msrv_nodes WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNodeUnknown
	}
	return n, err
}

// CreateNode registers a pending node and returns its one-time join token.
func (s *Store) CreateNode(ctx context.Context, name, address string, roles []string, actor int64) (*Node, string, int64, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if !nameRE.MatchString(name) {
		return nil, "", 0, ErrBadName
	}
	if !ValidAddress(address) {
		return nil, "", 0, ErrBadAddress
	}
	roles, err := NormalizeRoles(roles)
	if err != nil {
		return nil, "", 0, err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, "", 0, err
	}
	defer tx.Rollback() //nolint:errcheck
	var dup int
	_ = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM msrv_nodes WHERE name=?`, name).Scan(&dup)
	if dup > 0 {
		return nil, "", 0, ErrNameTaken
	}
	now := s.now().Unix()
	res, err := tx.ExecContext(ctx, `INSERT INTO msrv_nodes(name,address,roles,status,created_at) VALUES(?,?,?,'pending',?)`,
		name, address, strings.Join(roles, ","), now)
	if err != nil {
		return nil, "", 0, err
	}
	id, _ := res.LastInsertId()
	tok, exp, err := s.insertToken(ctx, tx, id, "join", actor)
	if err != nil {
		return nil, "", 0, err
	}
	if err := tx.Commit(); err != nil {
		return nil, "", 0, err
	}
	n, err := s.Get(ctx, id)
	return n, tok, exp, err
}

func (s *Store) insertToken(ctx context.Context, tx *sql.Tx, nodeID int64, purpose string, actor int64) (string, int64, error) {
	tok, err := newToken()
	if err != nil {
		return "", 0, err
	}
	now := s.now()
	exp := now.Add(TokenTTL).Unix()
	// a new token supersedes every unused one of the node
	if _, err := tx.ExecContext(ctx, `UPDATE msrv_join_tokens SET used_at=? WHERE node_id=? AND used_at=0`, now.Unix(), nodeID); err != nil {
		return "", 0, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO msrv_join_tokens(node_id,token_hash,purpose,created_by,created_at,expires_at) VALUES(?,?,?,?,?,?)`,
		nodeID, HashToken(tok), purpose, actor, now.Unix(), exp); err != nil {
		return "", 0, err
	}
	return tok, exp, nil
}

// NewRotateToken issues a token with which the node re-enrols (fresh key,
// new certificate, old serial revoked).
func (s *Store) NewRotateToken(ctx context.Context, nodeID, actor int64) (string, int64, error) {
	n, err := s.Get(ctx, nodeID)
	if err != nil {
		return "", 0, err
	}
	if n.Status == "revoked" {
		return "", 0, ErrRevoked
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return "", 0, err
	}
	defer tx.Rollback() //nolint:errcheck
	tok, exp, err := s.insertToken(ctx, tx, nodeID, "rotate", actor)
	if err != nil {
		return "", 0, err
	}
	return tok, exp, tx.Commit()
}

// Enrollment is what a successful join returns to the node.
type Enrollment struct {
	NodeID  int64    `json:"node_id"`
	Roles   []string `json:"roles"`
	CertPEM string   `json:"cert_pem"`
	CAPEM   string   `json:"ca_pem"`
}

// Enroll redeems a token (atomically, single use, unexpired) and signs csrPEM.
func (s *Store) Enroll(ctx context.Context, ca *CA, token string, csrPEM []byte) (*Enrollment, error) {
	if ca == nil {
		return nil, ErrCAUnusable
	}
	if !strings.HasPrefix(token, "bpj_") || len(token) > 128 {
		return nil, ErrTokenInvalid
	}
	now := s.now()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck
	var tid, nodeID int64
	err = tx.QueryRowContext(ctx, `SELECT id,node_id FROM msrv_join_tokens WHERE token_hash=? AND used_at=0 AND expires_at>?`,
		HashToken(token), now.Unix()).Scan(&tid, &nodeID)
	if err != nil {
		return nil, ErrTokenInvalid
	}
	// claim first: a concurrent redeem of the same token updates 0 rows
	res, err := tx.ExecContext(ctx, `UPDATE msrv_join_tokens SET used_at=? WHERE id=? AND used_at=0`, now.Unix(), tid)
	if err != nil {
		return nil, err
	}
	if c, _ := res.RowsAffected(); c != 1 {
		return nil, ErrTokenInvalid
	}
	var status, roles, oldSerial string
	if err := tx.QueryRowContext(ctx, `SELECT status,roles,cert_serial FROM msrv_nodes WHERE id=?`, nodeID).Scan(&status, &roles, &oldSerial); err != nil {
		return nil, ErrNodeUnknown
	}
	if status == "revoked" {
		return nil, ErrRevoked
	}
	rl := strings.Split(roles, ",")
	cert, certPEM, err := ca.SignNodeCSR(csrPEM, nodeID, rl, now)
	if err != nil {
		return nil, err
	}
	if oldSerial != "" {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO msrv_revoked(serial,node_id,reason,revoked_at) VALUES(?,?,?,?)`,
			oldSerial, nodeID, "rotated", now.Unix()); err != nil {
			return nil, err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE msrv_nodes SET status='active',cert_serial=?,cert_not_after=?,enrolled_at=? WHERE id=?`,
		SerialHex(cert.SerialNumber), cert.NotAfter.Unix(), now.Unix(), nodeID); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &Enrollment{NodeID: nodeID, Roles: rl, CertPEM: string(certPEM), CAPEM: string(ca.PEM)}, nil
}

// Revoke marks a node revoked and its current serial revoked.
func (s *Store) Revoke(ctx context.Context, nodeID int64, reason string) error {
	n, err := s.Get(ctx, nodeID)
	if err != nil {
		return err
	}
	now := s.now().Unix()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	if n.CertSerial != "" {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO msrv_revoked(serial,node_id,reason,revoked_at) VALUES(?,?,?,?)`, n.CertSerial, nodeID, reason, now); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE msrv_join_tokens SET used_at=? WHERE node_id=? AND used_at=0`, now, nodeID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE msrv_nodes SET status='revoked',health='down' WHERE id=?`, nodeID); err != nil {
		return err
	}
	return tx.Commit()
}

// RevokeSerial adds a serial (e.g. an old panel certificate) to the list.
func (s *Store) RevokeSerial(ctx context.Context, serial, reason string) error {
	_, err := s.DB.ExecContext(ctx, `INSERT OR IGNORE INTO msrv_revoked(serial,node_id,reason,revoked_at) VALUES(?,0,?,?)`,
		strings.ToLower(serial), reason, s.now().Unix())
	return err
}

// IsRevoked reports whether serial is on the revocation list.
func (s *Store) IsRevoked(serial string) bool {
	var n int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM msrv_revoked WHERE serial=?`, strings.ToLower(serial)).Scan(&n); err != nil {
		return true // fail closed
	}
	return n > 0
}

// RevokedSerials lists every revoked serial (pushed to agents).
func (s *Store) RevokedSerials(ctx context.Context) ([]string, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT serial FROM msrv_revoked ORDER BY serial`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// SetHealth stores the result of one health check.
func (s *Store) SetHealth(ctx context.Context, nodeID int64, ok bool, latency time.Duration, version, errMsg string, certNotAfter int64) error {
	now := s.now().Unix()
	if ok {
		_, err := s.DB.ExecContext(ctx, `UPDATE msrv_nodes SET last_check=?,last_seen=?,latency_ms=?,version=?,health='ok',health_error='',
			cert_not_after=CASE WHEN ?>0 THEN ? ELSE cert_not_after END WHERE id=?`,
			now, now, latency.Milliseconds(), version, certNotAfter, certNotAfter, nodeID)
		return err
	}
	if len(errMsg) > 300 {
		errMsg = errMsg[:300]
	}
	_, err := s.DB.ExecContext(ctx, `UPDATE msrv_nodes SET last_check=?,latency_ms=-1,health='down',health_error=? WHERE id=?`, now, errMsg, nodeID)
	return err
}

// SetAddress changes the node's agent address.
func (s *Store) SetAddress(ctx context.Context, nodeID int64, addr string) error {
	if !ValidAddress(addr) {
		return ErrBadAddress
	}
	res, err := s.DB.ExecContext(ctx, `UPDATE msrv_nodes SET address=? WHERE id=?`, addr, nodeID)
	if err != nil {
		return err
	}
	if c, _ := res.RowsAffected(); c == 0 {
		return ErrNodeUnknown
	}
	return nil
}
