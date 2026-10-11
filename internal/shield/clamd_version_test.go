package shield

import (
	"context"
	"errors"
	"testing"
)

// TestClamdVersionDisabled: ClamAV 1.5 answers VERSION with "COMMAND
// UNAVAILABLE". That reply must never become the engine version; the local
// clamscan --version is used instead, and without it the status says why.
func TestClamdVersionDisabled(t *testing.T) {
	ctx := context.Background()
	f, c := fakeClamd(t)
	f.Version = "COMMAND UNAVAILABLE"
	orig := localClamVersion
	t.Cleanup(func() { localClamVersion = orig })

	localClamVersion = func(context.Context) (string, error) {
		return "ClamAV 1.5.4/27789/Sat Oct 10 08:00:00 2026", nil
	}
	st := c.Status(ctx)
	if st.Version != "ClamAV 1.5.4" || st.SigVersion != "27789" {
		t.Fatalf("fallback status %+v", st)
	}

	localClamVersion = func(context.Context) (string, error) { return "", errors.New("no clamscan") }
	st = c.Status(ctx)
	if st.Status == StatusOK || st.Version == "COMMAND UNAVAILABLE" || st.Reason == "" {
		t.Fatalf("no-fallback status %+v", st)
	}
}
