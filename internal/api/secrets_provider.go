package api

// v0.4 baox: secret provider switch (local AES-256-GCM | OpenBao).
//
// Precedence: config `secrets.provider` (api.json) when set, otherwise the
// `secrets_provider` setting written by `bpanel secrets migrate`, otherwise
// "local". A misconfigured OpenBao never falls back silently to local (writes
// would land in the wrong place): the store reports unavailable with a reason.

import (
	"context"
	"errors"
	"fmt"

	"github.com/cumabozkurt/bpanel/internal/secrets"
	"github.com/cumabozkurt/bpanel/internal/store"
)

// SecretsConfig is the `secrets` block of api.json.
type SecretsConfig struct {
	Provider      string `json:"provider,omitempty"`       // "" | local | openbao
	OpenBaoConfig string `json:"openbao_config,omitempty"` // "" = /etc/bpanel/openbao.json
}

// SettingSecretsProvider is the settings key the migrate tool switches.
const SettingSecretsProvider = "secrets_provider"

// SecretsProviderName resolves which provider is active.
func SecretsProviderName(cfg Config, st *store.Store) string {
	if p := cfg.Secrets.Provider; p != "" {
		return p
	}
	if st != nil {
		if p := st.Get(SettingSecretsProvider, ""); p != "" {
			return p
		}
	}
	return "local"
}

// OpenSecretStore builds the named provider. For openbao, values sealed by
// the local provider before migration stay readable through Legacy when the
// local master key is still present.
func OpenSecretStore(cfg Config, st *store.Store, provider string) (secrets.SecretStore, error) {
	switch provider {
	case "local", "":
		return secrets.NewLocal(st.DB, cfg.SecretKeyFile)
	case "openbao":
		oc, err := secrets.LoadOpenBaoConfig(cfg.Secrets.OpenBaoConfig)
		if err != nil {
			return nil, err
		}
		ob, err := secrets.NewOpenBao(oc)
		if err != nil {
			return nil, err
		}
		if l, err := secrets.NewLocal(st.DB, cfg.SecretKeyFile); err == nil {
			ob.Legacy = l
		}
		return ob, nil
	}
	return nil, fmt.Errorf("unknown secrets provider %q", provider)
}

func (s *Server) newSecretStore() secrets.SecretStore {
	p := SecretsProviderName(s.Cfg, s.Store)
	st, err := OpenSecretStore(s.Cfg, s.Store, p)
	if err != nil {
		if s.Log != nil {
			s.Log.Error("secret store unavailable", "provider", p, "err", err)
		}
		if p == "local" {
			return unavailableStore{}
		}
		return unavailableStore{provider: p, reason: err.Error()}
	}
	return st
}

// MigrateSecrets copies every secret from the active provider to `to`,
// verifies each one, and only then records `to` as the active provider.
// The source is left untouched (rollback = migrate back, or set the setting).
func MigrateSecrets(ctx context.Context, cfg Config, st *store.Store, to string) (secrets.MigrateResult, string, error) {
	from := SecretsProviderName(cfg, st)
	if from == to {
		return secrets.MigrateResult{}, from, errors.New("source and destination provider are the same")
	}
	src, err := OpenSecretStore(cfg, st, from)
	if err != nil {
		return secrets.MigrateResult{}, from, fmt.Errorf("open %s: %w", from, err)
	}
	dst, err := OpenSecretStore(cfg, st, to)
	if err != nil {
		return secrets.MigrateResult{}, from, fmt.Errorf("open %s: %w", to, err)
	}
	if p, ok := dst.(interface{ Ping(context.Context) error }); ok {
		if err := p.Ping(ctx); err != nil {
			return secrets.MigrateResult{}, from, fmt.Errorf("%s not reachable: %w", to, err)
		}
	}
	res, err := secrets.Migrate(ctx, src, dst)
	if err != nil {
		return res, from, err
	}
	if err := st.Set(SettingSecretsProvider, to); err != nil {
		return res, from, err
	}
	return res, from, nil
}
