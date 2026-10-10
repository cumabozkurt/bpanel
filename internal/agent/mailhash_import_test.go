package agent

import "testing"

func TestImportedMailHash(t *testing.T) {
	for in, want := range map[string]string{
		"$6$abcdefgh$" + "x1234567890":  "{SHA512-CRYPT}$6$abcdefgh$x1234567890",
		"$5$rounds=5000$saltsalt$hashh": "{SHA256-CRYPT}$5$rounds=5000$saltsalt$hashh",
		"$2y$10$abcdefghijklmnopqrstuv": "{BLF-CRYPT}$2y$10$abcdefghijklmnopqrstuv",
		"$1$saltsalt$hashhash":          "{MD5-CRYPT}$1$saltsalt$hashhash",
		"$6$a:b$cdefghijkl":             "",
		"$6$abc\n$defghijkl":            "",
		"{PLAIN}secret":                 "",
		"!!":                            "",
		"$y$j9T$abcdefgh$ijk":           "",
	} {
		if got := ImportedMailHash(in); got != want {
			t.Errorf("%q -> %q want %q", in, got, want)
		}
	}
}
