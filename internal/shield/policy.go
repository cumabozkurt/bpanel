package shield

// Action the policy engine decides for a file.
type Action string

const (
	ActAllow        Action = "allow"
	ActAllowWarning Action = "allow_with_warning" // allowed, but recorded and shown
	ActBlock        Action = "block"              // upload refused / file not placed
	ActQuarantine   Action = "quarantine"         // moved to encrypted quarantine
	ActHold         Action = "hold"               // kept in staging until an admin decides
)

// AccountPolicy is the per-account (or server default) Shield policy. Zero
// values fall back to DefaultPolicy.
type AccountPolicy struct {
	OnInfected          Action `json:"on_infected,omitempty"`
	OnSuspiciousScript  Action `json:"on_suspicious_script,omitempty"`
	OnSuspiciousOther   Action `json:"on_suspicious_other,omitempty"`
	OnSuspiciousArchive Action `json:"on_suspicious_archive,omitempty"` // incl. rejected archives (bomb, zip-slip)
	OnUnavailableScript Action `json:"on_unavailable_script,omitempty"` // scanner down / timeout, script or executable
	OnUnavailableOther  Action `json:"on_unavailable_other,omitempty"`
}

// DefaultPolicy: fail closed for scripts and executables.
func DefaultPolicy() AccountPolicy {
	return AccountPolicy{OnInfected: ActQuarantine, OnSuspiciousScript: ActHold, OnSuspiciousOther: ActAllowWarning, OnSuspiciousArchive: ActBlock,
		OnUnavailableScript: ActBlock, OnUnavailableOther: ActAllowWarning}
}

// Decision is the policy result. Record is true for every action except a
// clean allow: nothing non-clean is ever allowed silently.
type Decision struct {
	Action Action `json:"action"`
	Reason string `json:"reason"`
	Record bool   `json:"record"`
}

func pick(v, def Action) Action {
	if v == "" {
		return def
	}
	return v
}

// Decide maps (outcome, file class, policy) to an action.
func Decide(out Outcome, class FileClass, p AccountPolicy) Decision {
	d := DefaultPolicy()
	risky := class == ClassScript || class == ClassExecutable
	var a Action
	var why string
	switch out {
	case OutClean:
		return Decision{Action: ActAllow, Reason: "clean"}
	case OutInfected:
		a, why = pick(p.OnInfected, d.OnInfected), "infected"
		if a == ActAllow || a == ActAllowWarning { // never allow known malware
			a = ActQuarantine
		}
	case OutSuspicious:
		switch {
		case risky:
			a, why = pick(p.OnSuspiciousScript, d.OnSuspiciousScript), "suspicious "+string(class)
		case class == ClassArchive:
			a, why = pick(p.OnSuspiciousArchive, d.OnSuspiciousArchive), "suspicious archive"
		default:
			a, why = pick(p.OnSuspiciousOther, d.OnSuspiciousOther), "suspicious file"
		}
	case OutUnavailable, OutTimeout:
		if risky || class == ClassArchive {
			a, why = pick(p.OnUnavailableScript, d.OnUnavailableScript), string(out)+" for "+string(class)
		} else {
			a, why = pick(p.OnUnavailableOther, d.OnUnavailableOther), string(out)
		}
	default:
		a, why = ActBlock, "unknown outcome "+string(out)
	}
	if a == ActAllow {
		a = ActAllowWarning
	}
	return Decision{Action: a, Reason: why, Record: true}
}
