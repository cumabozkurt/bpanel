package agentrpc

// v0.4 msrv (spec §16): methods used over the remote mTLS listener.
const (
	// MMsrvRevokedSet replaces the node's list of revoked certificate serials
	// (consulted on every remote handshake).
	MMsrvRevokedSet = "msrv.revoked.set"
)

type MsrvRevokedSetParams struct {
	Serials []string `json:"serials"`
}

type MsrvRevokedSetResult struct {
	Count int `json:"count"`
}
