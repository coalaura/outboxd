package config

import (
	"strings"
	"testing"
)

type allowedSenderCase struct {
	addr string
	want bool
}

func TestUserAllowsCaseInsensitive(t *testing.T) {
	u := User{
		Username:       "alice",
		AllowedSenders: []string{"User.Name@example.com", "*@lists.example.com"},
	}

	tests := []allowedSenderCase{
		{"User.Name@Example.com", true},
		{"user.name@example.com", true},
		{"USER.NAME@EXAMPLE.COM", true},
		{"other@example.com", false},
		{"any@lists.example.com", true},
		{"Any@Lists.Example.COM", true},
		{"any@other.example.com", false},
		{"", false},
		{"nodomain", false},
		{"@example.com", false},
	}

	for _, tc := range tests {
		got := u.Allows(tc.addr)
		if got != tc.want {
			t.Errorf("Allows(%q)=%v want %v", tc.addr, got, tc.want)
		}
	}
}

func TestUserValidateWildcardSender(t *testing.T) {
	u := User{
		Username:       "w",
		PasswordHash:   "$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		AllowedSenders: []string{"*@Example.COM"},
		Enabled:        true,
	}

	// Need real hash for ValidatePHC if used - Validate only checks prefix.
	err := u.Validate()
	if err != nil {
		t.Fatal(err)
	}

	if u.AllowedSenders[0] != "*@example.com" {
		t.Fatalf("wildcard=%q", u.AllowedSenders[0])
	}

	if !u.Allows("someone@example.com") {
		t.Fatal("wildcard should match")
	}
}

func TestAllowedSenderUsesStrictMailboxLimits(t *testing.T) {
	u := User{
		Username:       "alice",
		PasswordHash:   "$argon2id$placeholder",
		AllowedSenders: []string{strings.Repeat("a", 65) + "@example.com"},
	}
	if err := u.Validate(); err == nil {
		t.Fatal("overlong configured sender accepted")
	}
}
