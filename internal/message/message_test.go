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

func TestEightBitCharsetInferenceRequiresValidUTF8(t *testing.T) {
	valid := []byte("From: a@b.co\r\n\r\ncaf\xc3\xa9\r\n")
	msg, err := Prepare(bytes.NewReader(valid), Options{Hostname: "h"})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(msg.Data, []byte("charset=utf-8")) {
		t.Fatal("valid UTF-8 body did not infer UTF-8 charset")
	}

	invalid := []byte("From: a@b.co\r\n\r\nbad\xff\r\n")
	if _, err := Prepare(bytes.NewReader(invalid), Options{Hostname: "h"}); err == nil {
		t.Fatal("invalid UTF-8 8-bit body accepted with inferred semantics")
	}
}

func TestRejectsInvalidUTF8Header(t *testing.T) {
	raw := []byte("From: a@b.co\r\nSubject: bad\xff\xfe\r\n\r\nbody\r\n")
	_, err := Prepare(bytes.NewReader(raw), Options{Hostname: "h"})
	if err == nil {
		t.Fatal("expected invalid UTF-8 rejection")
	}
}

func TestEncodedWordDoesNotRequireSMTPUTF8(t *testing.T) {
	raw := "From: a@b.co\r\nTo: c@d.co\r\nSubject: =?utf-8?q?caf=C3=A9?=\r\n\r\nbody\r\n"
	msg, err := Prepare(strings.NewReader(raw), Options{Hostname: "h"})
	if err != nil {
		t.Fatal(err)
	}
	if msg.NeedsUTF8 {
		t.Fatal("ASCII encoded-words must not require SMTPUTF8")
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
