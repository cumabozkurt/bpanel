package api

import (
	"bufio"
	"net"
	"strings"
	"testing"
)

// The local MTA advertises STARTTLS with a certificate that never matches
// 127.0.0.1; alerts must still be delivered over loopback.
func TestObsxLocalSendMailNoStartTLS(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		w := func(s string) { _, _ = c.Write([]byte(s + "\r\n")) }
		w("220 test ESMTP")
		var body strings.Builder
		data := false
		for {
			l, err := r.ReadString('\n')
			if err != nil {
				return
			}
			if data {
				if l == ".\r\n" {
					data = false
					w("250 ok")
					continue
				}
				body.WriteString(l)
				continue
			}
			switch cmd := strings.ToUpper(strings.TrimSpace(l)); {
			case strings.HasPrefix(cmd, "EHLO"):
				w("250-test")
				w("250 STARTTLS")
			case strings.HasPrefix(cmd, "STARTTLS"):
				w("454 should not be used")
			case cmd == "DATA":
				data = true
				w("354 go")
			case cmd == "QUIT":
				w("221 bye")
				got <- body.String()
				return
			default:
				w("250 ok")
			}
		}
	}()
	if err := obsxLocalSendMail(ln.Addr().String(), nil, "a@h.test", []string{"b@h.test"}, []byte("Subject: t\r\n\r\nhello\r\n")); err != nil {
		t.Fatal(err)
	}
	if b := <-got; !strings.Contains(b, "hello") {
		t.Fatalf("body %q", b)
	}
}
