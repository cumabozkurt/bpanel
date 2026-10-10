package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	rpc "github.com/cumabozkurt/bpanel/internal/agentrpc"
)

// The agent exposes a fixed set of typed actions; none may run an arbitrary shell command.
func TestNoShellLikeActions(t *testing.T) {
	a := New(DefaultConfig(), nil, nil)
	if len(a.routes) < 40 {
		t.Fatalf("expected the full typed action table, got %d", len(a.routes))
	}
	for m := range a.routes {
		for _, bad := range []string{"shell", "exec", "command", "run_raw", "bash"} {
			if strings.Contains(strings.ToLower(m), bad) {
				t.Errorf("action %q looks like a raw command runner", m)
			}
		}
	}
}

// Typed parameters reject unknown fields, so a caller cannot smuggle extra input.
func TestUnknownFieldsRejected(t *testing.T) {
	a := New(DefaultConfig(), nil, nil)
	h := a.routes[rpc.MCronSet]
	_, err := h(context.Background(), json.RawMessage(`{"user":"demo","cmd":"rm -rf /"}`))
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("expected unknown-field rejection, got %v", err)
	}
}
