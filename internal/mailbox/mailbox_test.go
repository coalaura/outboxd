package mailbox_test

import (
	"strings"
	"testing"

	"github.com/coalaura/outboxd/internal/mailbox"
)

func TestRoutingDomainASCII(t *testing.T) {
	got, err := mailbox.RoutingDomain("Example.COM")
	if err != nil {
		t.Fatal(err)
	}
	if got != "example.com" {
		t.Fatalf("got %q want example.com", got)
	}
}

func TestRoutingDomainExactALabel(t *testing.T) {
	got, err := mailbox.RoutingDomain("exämple.com")
	if err != nil {
		t.Fatal(err)
	}
	const want = "xn--exmple-cua.com"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	again, err := mailbox.RoutingDomain(got)
	if err != nil {
		t.Fatal(err)
	}
	if again != want {
		t.Fatalf("A-label not idempotent: %q", again)
	}
}

func TestDomainOfUnicode(t *testing.T) {
	addr := "user@exämple.com"
	got, err := mailbox.DomainOf(addr)
	if err != nil {
		t.Fatal(err)
	}
	if got != "xn--exmple-cua.com" {
		t.Fatalf("got %q", got)
	}
}

func TestRoutingDomainRejects(t *testing.T) {
	cases := []string{
		"",
		".",
		"..",
		"foo.",
		".foo.com",
		"foo..com",
		"a",
		string([]byte{0xff, 0xfe}) + ".com",
		strings.Repeat("a", 64) + ".com",
		strings.Repeat("a", 250) + ".com",
		" example.com",
		"example.com ",
		"\texample.com",
		"_smtp.example.com",
		"xn--abc.com",       // invalid A-label
		"a\u200d.com",       // joiner misuse
		"\u05d0\u05d1c.com", // invalid bidi mixed RTL without rule satisfaction (profile rejects)
	}
	for _, c := range cases {
		if _, err := mailbox.RoutingDomain(c); err == nil {
			t.Fatalf("expected reject for %q", c)
		}
	}
	// Overlong domain after conversion (>253).
	var b strings.Builder
	for i := 0; i < 40; i++ {
		if i > 0 {
			b.WriteByte('.')
		}
		b.WriteString("abcdefghij")
	}
	if _, err := mailbox.RoutingDomain(b.String()); err == nil {
		t.Fatal("expected overlong domain reject")
	}
}

func TestDomainOfLocalPartUntouched(t *testing.T) {
	d, err := mailbox.DomainOf("User.Name@Example.COM")
	if err != nil {
		t.Fatal(err)
	}
	if d != "example.com" {
		t.Fatalf("got %q", d)
	}
}

func TestInvalidUTF8Rejected(t *testing.T) {
	_, err := mailbox.RoutingDomain(string([]byte{0xff, 0xfe}) + ".com")
	if err != mailbox.ErrInvalidUTF8 {
		t.Fatalf("got %v want ErrInvalidUTF8", err)
	}
}
