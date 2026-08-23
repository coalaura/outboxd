package main

import "testing"

func TestOpenPGPCommandRequiresExactArguments(t *testing.T) {
	tests := []struct {
		args  []string
		usage string
	}{
		{args: nil, usage: "usage: outboxd openpgp <create|publish> ..."},
		{args: []string{"create"}, usage: "usage: outboxd openpgp create <username> <sender>"},
		{args: []string{"create", "alice"}, usage: "usage: outboxd openpgp create <username> <sender>"},
		{args: []string{"create", "alice", "alice@example.com", "extra"}, usage: "usage: outboxd openpgp create <username> <sender>"},
		{args: []string{"publish"}, usage: "usage: outboxd openpgp publish <output-directory>"},
		{args: []string{"publish", "one", "two"}, usage: "usage: outboxd openpgp publish <output-directory>"},
		{args: []string{"unknown"}, usage: "usage: outboxd openpgp <create|publish> ..."},
	}

	for _, test := range tests {
		err := openPGPCommand("unused.yml", test.args)
		if err == nil || err.Error() != test.usage {
			t.Fatalf("args=%q error=%v", test.args, err)
		}
	}
}
