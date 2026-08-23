package queue

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/coalaura/outboxd/internal/mailbox"
)

func sanitize(s string) string {
	var b strings.Builder

	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}

	if b.Len() == 0 {
		return "x"
	}

	return b.String()
}

func validateEnvelope(e *Envelope) error {
	err := ValidateID(e.ID)
	if err != nil {
		return err
	}

	if len(e.Incarnation) != 32 {
		return errors.New("invalid queue incarnation")
	}

	_, err = hex.DecodeString(e.Incarnation)
	if err != nil {
		return errors.New("invalid queue incarnation")
	}

	if e.Revision == 0 || e.Revision > maxEnvelopeRevision {
		return errors.New("invalid queue revision")
	}

	if e.Username == "" {
		return errors.New("missing username")
	}

	if len(e.Username) > maxEnvelopeStringBytes {
		return errors.New("username too long")
	}

	if len(e.LastError) > maxEnvelopeDetailBytes {
		return errors.New("last error too long")
	}

	if e.DSNSourceID != "" {
		err := ValidateID(e.DSNSourceID)
		if err != nil {
			return fmt.Errorf("DSN source: %w", err)
		}

		if len(e.DSNSourceIncarnation) != 32 {
			return errors.New("invalid DSN source incarnation")
		}

		_, err = hex.DecodeString(e.DSNSourceIncarnation)
		if err != nil {
			return errors.New("invalid DSN source incarnation")
		}

		if e.ID != DSNID(e.DSNSourceID, e.DSNSourceIncarnation, e.DSNGeneration) {
			return fmt.Errorf("%w: derived DSN ID mismatch", ErrIDConflict)
		}

		if e.DSNSourceRevision == 0 || e.DSNSourceRevision > maxEnvelopeRevision {
			return errors.New("invalid DSN source revision")
		}

		if e.DSNID != "" {
			return errors.New("DSN cannot link another DSN")
		}

		if e.Sender != "" {
			return errors.New("DSN sender must be empty")
		}
	} else if e.Sender != "" {
		if e.DSNSourceRevision != 0 {
			return errors.New("DSN source revision without source ID")
		}
		if e.DSNSourceIncarnation != "" {
			return errors.New("DSN source incarnation without source ID")
		}

		err := validateAddress(e.Sender)
		if err != nil {
			return fmt.Errorf("sender: %w", err)
		}
	} else {
		return errors.New("missing sender")
	}

	if e.DSNID != "" && e.DSNID != DSNID(e.ID, e.Incarnation, e.DSNGeneration) {
		return fmt.Errorf("%w: source DSN link mismatch", ErrIDConflict)
	}

	if len(e.Recipients) == 0 {
		return errors.New("no recipients")
	}

	if len(e.Recipients) > maxEnvelopeRecipients {
		return fmt.Errorf("too many recipients: maximum is %d", maxEnvelopeRecipients)
	}

	if e.Created.IsZero() {
		return errors.New("missing created timestamp")
	}

	if e.Attempts < 0 || e.Attempts > maxEnvelopeAttempts {
		return errors.New("invalid attempts")
	}

	if e.Size < 0 {
		return errors.New("negative size")
	}

	if !validBodyDigest(e.BodyDigest) {
		return errors.New("missing or invalid body digest")
	}

	if len(e.Bodies) > len(e.Recipients) {
		return errors.New("more message bodies than recipients")
	}

	usedBodies := make([]bool, len(e.Bodies))

	var bodyEnd int64

	for i, body := range e.Bodies {
		if body.Offset != bodyEnd || body.Size <= 0 || body.Size > e.Size-body.Offset {
			return fmt.Errorf("body[%d]: invalid range", i)
		}

		if !validBodyDigest(body.Digest) {
			return fmt.Errorf("body[%d]: invalid digest", i)
		}

		bodyEnd += body.Size
	}

	if len(e.Bodies) != 0 && bodyEnd != e.Size {
		return errors.New("message bodies do not cover stored body")
	}

	var needUTF8 bool

	if e.Sender != "" && addressHasNonASCII(e.Sender) {
		needUTF8 = true
	}

	for i := range e.Recipients {
		r := &e.Recipients[i]

		if len(e.Bodies) == 0 {
			if r.Body != 0 {
				return fmt.Errorf("recipient[%d]: body index without message bodies", i)
			}
		} else {
			if r.Body < 0 || r.Body >= len(e.Bodies) {
				return fmt.Errorf("recipient[%d]: invalid body index", i)
			}

			usedBodies[r.Body] = true
		}

		if len(r.Domain) > maxEnvelopeStringBytes {
			return fmt.Errorf("recipient[%d]: domain too long", i)
		}

		if len(r.Detail) > maxEnvelopeDetailBytes {
			return fmt.Errorf("recipient[%d]: detail too long", i)
		}

		if containsDisplayControl(r.Detail) {
			return fmt.Errorf("recipient[%d]: detail contains display control characters", i)
		}

		switch r.Status {
		case "":
			r.Status = StatusPending
		case StatusPending, StatusSent, StatusFailed:
		default:
			return fmt.Errorf("recipient[%d]: invalid status %q", i, r.Status)
		}

		if r.Code != 0 && (r.Code < 200 || r.Code > 599) {
			return fmt.Errorf("recipient[%d]: invalid SMTP code", i)
		}

		if r.EnhancedCode != "" && (r.Code == 0 || !validEnhancedCode(r.EnhancedCode, r.Code)) {
			return fmt.Errorf("recipient[%d]: invalid enhanced SMTP code", i)
		}

		switch r.Status {
		case StatusPending:
			if r.Code != 0 || r.EnhancedCode != "" {
				return fmt.Errorf("recipient[%d]: pending recipient has a terminal SMTP code", i)
			}
		case StatusSent:
			if r.Code != 0 && r.Code/100 != 2 {
				return fmt.Errorf("recipient[%d]: sent recipient has a non-success SMTP code", i)
			}
		case StatusFailed:
			if r.Code != 0 && r.Code/100 != 5 {
				return fmt.Errorf("recipient[%d]: failed recipient has a non-permanent SMTP code", i)
			}
		}

		err := validateAddress(r.Address)
		if err != nil {
			return fmt.Errorf("recipient[%d]: %w", i, err)
		}

		if addressHasNonASCII(r.Address) {
			needUTF8 = true
		}

		routing, err := mailbox.DomainOf(r.Address)
		if err != nil {
			return fmt.Errorf("recipient[%d]: %w", i, err)
		}

		if r.Domain == "" {
			r.Domain = routing
		} else {
			// Accept a stored routing domain only when it normalizes to the same A-label.
			// Unicode routing domains left by older builds are rewritten to the A-label.
			stored, err := mailbox.RoutingDomain(r.Domain)
			if err != nil || stored != routing {
				return fmt.Errorf("recipient[%d]: domain mismatch", i)
			}

			r.Domain = routing
		}
	}

	for i, used := range usedBodies {
		if !used {
			return fmt.Errorf("body[%d]: not referenced by a recipient", i)
		}
	}

	// Non-ASCII envelope addresses require the SMTPUTF8 flag so outbound MAIL/RCPT
	// never emit UTF-8 without the SMTPUTF8 MAIL parameter. ASCII envelopes may set
	// the flag when headers independently require it; the flag is never cleared here.
	if needUTF8 && !e.SMTPUTF8 {
		return errors.New("SMTPUTF8 required for non-ASCII envelope address")
	}

	if !envelopeMetadataWithinLimit(e) {
		return fmt.Errorf("envelope metadata exceeds %d bytes", maxEnvelopeMetadata)
	}

	return nil
}

func validBodyDigest(digest string) bool {
	if len(digest) != len(bodyDigestPrefix)+sha256.Size*2 || !strings.HasPrefix(digest, bodyDigestPrefix) {
		return false
	}

	digestBytes, err := hex.DecodeString(strings.TrimPrefix(digest, bodyDigestPrefix))
	if err != nil {
		return false
	}

	return bodyDigestPrefix+hex.EncodeToString(digestBytes) == digest
}

func containsDisplayControl(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) {
			return true
		}
	}

	return false
}

func incrementRevision(revision uint64) (uint64, error) {
	if revision == 0 || revision >= maxEnvelopeRevision {
		return 0, errors.New("queue revision cannot be incremented")
	}

	return revision + 1, nil
}

func envelopeMetadataWithinLimit(e *Envelope) bool {
	// JSON can expand a byte to a six-byte escape. Include ample fixed overhead
	// per envelope and recipient so validation rejects before marshaling.
	remaining := int64(maxEnvelopeMetadata) - 2048 - int64(len(e.Recipients))*256

	strings := []string{
		e.ID, e.Incarnation, e.Username, e.Sender, e.LastError, e.BodyDigest, e.DSNID,
		e.DSNSourceID, e.DSNSourceIncarnation,
	}

	for i := range e.Recipients {
		strings = append(strings, e.Recipients[i].Address, e.Recipients[i].Domain, string(e.Recipients[i].Status), e.Recipients[i].Detail, e.Recipients[i].EnhancedCode)
	}

	for _, value := range strings {
		if int64(len(value)) > remaining/6 {
			return false
		}

		remaining -= int64(len(value)) * 6
	}

	return remaining >= 0
}

func validEnhancedCode(enhanced string, code int) bool {
	parts := strings.Split(enhanced, ".")
	if len(parts) != 3 || len(parts[0]) != 1 || (parts[0] != "2" && parts[0] != "4" && parts[0] != "5") {
		return false
	}

	if code != 0 && int(parts[0][0]-'0') != code/100 {
		return false
	}

	for _, part := range parts[1:] {
		if len(part) < 1 || len(part) > 3 {
			return false
		}

		for i := range len(part) {
			if part[i] < '0' || part[i] > '9' {
				return false
			}
		}
	}

	return true
}

// addressHasNonASCII reports whether addr contains any octet above 0x7F.
// Addresses must already be valid UTF-8 (enforced by validateAddress).
func addressHasNonASCII(addr string) bool {
	for i := 0; i < len(addr); i++ {
		if addr[i] >= 0x80 {
			return true
		}
	}

	return false
}

func validateAddress(addr string) error {
	if addr == "" {
		return errors.New("empty address")
	}

	if !utf8.ValidString(addr) {
		return errors.New("invalid utf-8")
	}

	if len(addr) > maxEnvelopeStringBytes {
		return errors.New("address too long")
	}

	for i := 0; i < len(addr); i++ {
		if addr[i] < 0x20 || addr[i] == 0x7f {
			return errors.New("control character in address")
		}
	}

	at := strings.LastIndexByte(addr, '@')
	if at <= 0 || at == len(addr)-1 {
		return errors.New("missing @domain")
	}

	if strings.Contains(addr, " ") {
		return errors.New("whitespace in address")
	}

	return nil
}
