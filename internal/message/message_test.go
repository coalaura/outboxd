package message

import (
	"bytes"
	"strings"
	"testing"
)

func TestPrepareStripsBccResentBccReturnPath(t *testing.T) {
	raw := "" +
		"From: Alice <Alice@Example.COM>\r\n" +
		"To: bob@example.com\r\n" +
		"Bcc: secret@example.com\r\n" +
		"Resent-Bcc: other@example.com\r\n" +
		"Return-Path: <bounce@example.com>\r\n" +
		"Subject: hi\r\n" +
		"\r\n" +
		"body\r\n"
	msg, err := Prepare(strings.NewReader(raw), Options{Hostname: "mail.example.com", Helo: "client"})
	if err != nil {
		t.Fatal(err)
	}
	s := string(msg.Data)
	for _, bad := range []string{"Bcc:", "Resent-Bcc:", "Return-Path:"} {
		if strings.Contains(s, bad) {
			t.Fatalf("outgoing still contains %s", bad)
		}
	}
}

func TestFromPreservesLocalPartCase(t *testing.T) {
	raw := "From: User.Name@Example.COM\r\nTo: a@b.co\r\nSubject: x\r\n\r\nhi\r\n"
	msg, err := Prepare(strings.NewReader(raw), Options{Hostname: "mail.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if msg.From != "User.Name@example.com" {
		t.Fatalf("From=%q", msg.From)
	}
}

func TestEightBitAndUTF8Flags(t *testing.T) {
	raw := "From: a@b.co\r\nTo: c@d.co\r\nSubject: caf\xc3\xa9\r\n\r\n" + "body\xc3\xa9\r\n"
	msg, err := Prepare(bytes.NewReader([]byte(raw)), Options{Hostname: "mail.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !msg.EightBit {
		t.Fatal("expected EightBit")
	}
	if !msg.NeedsUTF8 {
		t.Fatal("expected NeedsUTF8 for raw UTF-8 subject")
	}
}

func TestRejectsControlInHeader(t *testing.T) {
	raw := "From: a@b.co\r\nSub\x01ject: x\r\n\r\nbody\r\n"
	_, err := Prepare(strings.NewReader(raw), Options{Hostname: "h"})
	if err == nil {
		t.Fatal("expected malformed")
	}
}

func TestRejectsMalformedFolding(t *testing.T) {
	raw := "From: a@b.co\r\n\t\r\nTo: c@d.co\r\n\r\nbody\r\n"
	_, err := Prepare(strings.NewReader(raw), Options{Hostname: "h"})
	if err == nil {
		t.Fatal("expected malformed folding")
	}
}

func TestReplacesBadDateAndMessageID(t *testing.T) {
	raw := "From: a@b.co\r\nTo: c@d.co\r\nDate: not-a-date\r\nMessage-ID: bad\r\nSubject: x\r\n\r\nbody\r\n"
	msg, err := Prepare(strings.NewReader(raw), Options{Hostname: "mail.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	s := string(msg.Data)
	if strings.Contains(s, "Date: not-a-date") {
		t.Fatal("bad Date retained")
	}
	if strings.Contains(s, "Message-ID: bad") {
		t.Fatal("bad Message-ID retained")
	}
	if !strings.Contains(s, "Message-ID: <") {
		t.Fatal("missing replacement Message-ID")
	}
}

func TestMaxBytes(t *testing.T) {
	raw := "From: a@b.co\r\nTo: c@d.co\r\nSubject: x\r\n\r\n" + strings.Repeat("x", 100)
	_, err := Prepare(strings.NewReader(raw), Options{Hostname: "h", MaxBytes: 40})
	if err != ErrOversized {
		t.Fatalf("err=%v", err)
	}
}

func TestKeepsValidMessageID(t *testing.T) {
	raw := "From: a@b.co\r\nTo: c@d.co\r\nMessage-ID: <abc@example.com>\r\nSubject: x\r\n\r\nbody\r\n"
	msg, err := Prepare(strings.NewReader(raw), Options{Hostname: "mail.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if msg.ID != "<abc@example.com>" {
		t.Fatalf("ID=%q", msg.ID)
	}
	// Should appear only once.
	if strings.Count(string(msg.Data), "Message-ID:") != 1 {
		t.Fatal("duplicate Message-ID")
	}
}
