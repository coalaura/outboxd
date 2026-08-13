package main

import "testing"

func TestOpenPGPCommandRequiresExactArguments(t *testing.T) {
	for _, args := range [][]string{nil, {"create"}, {"create", "alice"}, {"create", "alice", "alice@example.com", "extra"}, {"unknown", "alice", "alice@example.com"}} {
		err := openPGPCommand("unused.yml", args)
		if err == nil || err.Error() != "usage: outboxd openpgp create <username> <sender>" {
			t.Fatalf("args=%q error=%v", args, err)
		}
	}
}
