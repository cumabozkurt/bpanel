package mailx

import "testing"

func TestNormalizeEntryWildcardDomain(t *testing.T) {
	for in, want := range map[string]string{"*@Spammer.example": "@spammer.example", "@a.test": "@a.test", "a.test": "@a.test", "u@a.test": "u@a.test"} {
		if got, ok := NormalizeEntry(in); !ok || got != want {
			t.Errorf("%q -> %q %v, want %q", in, got, ok, want)
		}
	}
}
