package config

import "testing"

func TestUserAllowsCaseInsensitive(t *testing.T) {
	u := User{
		Username:       "alice",
		AllowedSenders: []string{"User.Name@example.com", "*@lists.example.com"},
	}

	tests := []struct {
		addr string
		want bool
	}{
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
		if got := u.Allows(tc.addr); got != tc.want {
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
	if err := u.Validate(); err != nil {
		t.Fatal(err)
	}
	if u.AllowedSenders[0] != "*@example.com" {
		t.Fatalf("wildcard=%q", u.AllowedSenders[0])
	}
	if !u.Allows("someone@example.com") {
		t.Fatal("wildcard should match")
	}
}
