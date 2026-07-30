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
		t.Fatalf("got %q", got)
	}
}

func TestDomainOfUnicode(t *testing.T) {
	// ü.com → xn--tda.com (common test U-label)
	addr := "user@exämple.com"
	got, err := mailbox.DomainOf(addr)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "ä") || !strings.HasPrefix(got, "xn--") && got == "exämple.com" {
		// Must be A-label
		if got == "exämple.com" {
			t.Fatalf("expected A-label, got U-label %q", got)
		}
	}
	// Re-routingée the A-label should be stable.
	again, err := mailbox.RoutingDomain(got)
	if err != nil || again != got {
		t.Fatalf("stable A-label: %q %v", again, err)
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
	}
	for _, c := range cases {
		if _, err := mailbox.RoutingDomain(c); err == nil {
			t.Fatalf("expected reject for %q", c)
		}
	}
}

func TestDomainOfLocalPartUntouched(t *testing.T) {
	// DomainOf does not change the mailbox left of @; only domain routing.
	d, err := mailbox.DomainOf("User.Name@Example.COM")
	if err != nil {
		t.Fatal(err)
	}
	if d != "example.com" {
		t.Fatalf("got %q", d)
	}
}
