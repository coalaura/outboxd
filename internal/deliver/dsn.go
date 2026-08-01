package deliver

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/coalaura/outboxd/internal/mailbox"
	"github.com/coalaura/outboxd/internal/queue"
)

func (d *Deliverer) ensureDSN(envelope *queue.Envelope) error {
	if envelope.DSNID != "" || envelope.DSNSourceID != "" || envelope.Sender == "" {
		return nil
	}

	if envelope.Failed() == 0 {
		return nil
	}

	dsnID := dsnEnvelopeID(envelope.ID, envelope.Incarnation, envelope.DSNGeneration)

	reader, err := d.queue.Reader(envelope.ID)
	if err != nil {
		return err
	}

	body, err := readDSNOriginal(reader)
	if err != nil {
		return err
	}

	msg, err := buildDSN(d.cfg.Server.Hostname, envelope, body)
	if err != nil {
		return err
	}

	if d.signer != nil {
		sig, err := d.signer.Signature(msg)
		if err != nil {
			return fmt.Errorf("dsn dkim: %w", err)
		}

		signed := make([]byte, 0, len(sig)+len(msg))
		signed = append(signed, sig...)
		signed = append(signed, msg...)
		msg = signed
	}

	domain, err := mailbox.DomainOf(envelope.Sender)
	if err != nil {
		return fmt.Errorf("dsn recipient domain: %w", err)
	}

	needUTF8 := false

	for i := 0; i < len(envelope.Sender); i++ {
		if envelope.Sender[i] >= 0x80 {
			needUTF8 = true
			break
		}
	}

	// EightBit is required only when transmitted bytes contain high-bit octets,
	// not merely because a part declares an 8bit transfer encoding.
	eightBit := false

	for _, b := range msg {
		if b >= 0x80 {
			eightBit = true
			break
		}
	}

	now := time.Now()
	dsnEnv := &queue.Envelope{
		ID:       dsnID,
		Username: "mailer-daemon",
		Sender:   "",
		Recipients: []queue.Recipient{{
			Address: envelope.Sender,
			Domain:  domain,
			Status:  queue.StatusPending,
		}},
		Created:              now,
		NextAttempt:          now,
		DSNSourceID:          envelope.ID,
		DSNSourceIncarnation: envelope.Incarnation,
		DSNGeneration:        envelope.DSNGeneration,
		SMTPUTF8:             needUTF8,
		EightBit:             eightBit,
	}

	return d.queue.AddDSN(envelope, dsnEnv, msg)
}

const dsnOriginalLimit = 256 << 10

func readDSNOriginal(r io.ReadCloser) (original []byte, err error) {
	defer func() {
		closeErr := r.Close()
		if err == nil {
			err = closeErr
		}
	}()
	original, err = io.ReadAll(io.LimitReader(r, dsnOriginalLimit+1))
	if err != nil {
		return nil, err
	}

	if len(original) <= dsnOriginalLimit {
		return original, nil
	}

	end := bytes.Index(original, []byte("\r\n\r\n"))
	if end >= 0 {
		return original[:end+4], nil
	}

	return original[:dsnOriginalLimit], nil
}

func dsnEnvelopeID(original, incarnation string, generation uint64) string {
	return queue.DSNID(original, incarnation, generation)
}

func buildDSN(hostname string, env *queue.Envelope, original []byte) ([]byte, error) {
	if hostname == "" {
		hostname = "localhost"
	}

	boundary, err := randomBoundary()
	if err != nil {
		return nil, err
	}

	var failed []queue.Recipient

	for i := range env.Recipients {
		if env.Recipients[i].Status == queue.StatusFailed {
			failed = append(failed, env.Recipients[i])
		}
	}

	if len(failed) == 0 {
		return nil, errors.New("no failed recipients for DSN")
	}

	now := time.Now().UTC()
	msgID := fmt.Sprintf("<%s@%s>", dsnEnvelopeID(env.ID, env.Incarnation, env.DSNGeneration), hostname)

	var human bytes.Buffer
	fmt.Fprintf(&human, "This is the mail system at host %s.\r\n\r\n", hostname)
	human.WriteString("I'm sorry to have to inform you that your message could not\r\n")
	human.WriteString("be delivered to one or more recipients.\r\n\r\n")

	for _, r := range failed {
		fmt.Fprintf(&human, "<%s>: %s\r\n", r.Address, r.Detail)
	}

	var report bytes.Buffer
	fmt.Fprintf(&report, "Reporting-MTA: dns; %s\r\n", hostname)
	fmt.Fprintf(&report, "Arrival-Date: %s\r\n", now.Format(time.RFC1123Z))
	fmt.Fprintf(&report, "X-Original-Envelope-ID: %s\r\n", env.ID)

	for _, r := range failed {
		report.WriteString("\r\n")
		fmt.Fprintf(&report, "Final-Recipient: rfc822; %s\r\n", r.Address)
		report.WriteString("Action: failed\r\n")
		fmt.Fprintf(&report, "Status: %s\r\n", dsnStatus(r))

		if r.Detail != "" {
			fmt.Fprintf(&report, "Diagnostic-Code: smtp; %s\r\n", sanitizeHeader(r.Detail))
		}
	}

	orig := original
	if len(orig) == 0 {
		orig = []byte("\r\n")
	}

	if len(orig) > dsnOriginalLimit {
		idx := bytes.Index(orig, []byte("\r\n\r\n"))
		if idx >= 0 {
			orig = orig[:idx+4]
		}
	}

	var out bytes.Buffer
	fmt.Fprintf(&out, "From: Mail Delivery System <MAILER-DAEMON@%s>\r\n", hostname)
	fmt.Fprintf(&out, "To: <%s>\r\n", env.Sender)
	out.WriteString("Subject: Undelivered Mail Returned to Sender\r\n")
	fmt.Fprintf(&out, "Date: %s\r\n", now.Format(time.RFC1123Z))
	fmt.Fprintf(&out, "Message-ID: %s\r\n", msgID)
	out.WriteString("MIME-Version: 1.0\r\n")
	fmt.Fprintf(&out, "Content-Type: multipart/report; report-type=delivery-status;\r\n\tboundary=\"%s\"\r\n", boundary)
	out.WriteString("Auto-Submitted: auto-replied\r\n")
	out.WriteString("\r\n")

	fmt.Fprintf(&out, "--%s\r\n", boundary)
	out.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	out.WriteString("Content-Disposition: inline\r\n")
	out.WriteString("Content-Transfer-Encoding: 8bit\r\n\r\n")
	out.Write(human.Bytes())

	if !bytes.HasSuffix(human.Bytes(), []byte("\r\n")) {
		out.WriteString("\r\n")
	}

	fmt.Fprintf(&out, "\r\n--%s\r\n", boundary)
	out.WriteString("Content-Type: message/delivery-status\r\n")
	out.WriteString("Content-Description: Delivery report\r\n\r\n")
	out.Write(report.Bytes())

	if !bytes.HasSuffix(report.Bytes(), []byte("\r\n")) {
		out.WriteString("\r\n")
	}

	fmt.Fprintf(&out, "\r\n--%s\r\n", boundary)
	out.WriteString("Content-Type: message/rfc822\r\n")
	out.WriteString("Content-Description: Undelivered Message\r\n\r\n")
	out.Write(orig)

	if !bytes.HasSuffix(orig, []byte("\r\n")) {
		out.WriteString("\r\n")
	}

	fmt.Fprintf(&out, "\r\n--%s--\r\n", boundary)

	return out.Bytes(), nil
}

func dsnStatus(r queue.Recipient) string {
	if r.EnhancedCode != "" && parseEnhancedCode(r.Code, r.EnhancedCode) == r.EnhancedCode {
		return r.EnhancedCode
	}

	class := r.Code / 100
	if class == 4 || class == 5 {
		return fmt.Sprintf("%d.0.0", class)
	}

	return "5.0.0"
}

func randomBoundary() (string, error) {
	var b [12]byte

	_, err := rand.Read(b[:])
	if err != nil {
		return "", err
	}

	return "outboxd=" + hex.EncodeToString(b[:]), nil
}

func sanitizeHeader(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 200 {
		s = s[:200]

		for !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}

	return s
}
