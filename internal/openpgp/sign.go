package openpgp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net/mail"
	"path/filepath"
	"strings"
	"time"

	pgp "github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/coalaura/outboxd/internal/config"
)

const (
	maxKeyBytes        = 4 << 20
	maxPassphraseBytes = 4 << 10
	maxMultipartDepth  = 32
)

// ErrMessageTooLarge reports deterministic expansion beyond max_message_bytes.
var ErrMessageTooLarge = errors.New("signed message exceeds configured maximum size")

type identity struct {
	entity    *pgp.Entity
	autocrypt []byte
	gate      chan struct{}
}

// Signers is an immutable startup snapshot of configured signing identities.
type Signers struct {
	identities map[string]*identity
	maximum    int64
}

type limitedBuffer struct {
	bytes.Buffer
	maximum int64
	ctx     context.Context
}

type contextReader struct {
	ctx    context.Context
	reader *bytes.Reader
}

type contextWriter struct {
	ctx    context.Context
	writer *bytes.Buffer
}

func (b *limitedBuffer) Write(data []byte) (int, error) {
	if err := b.ctx.Err(); err != nil {
		return 0, err
	}

	if int64(b.Len())+int64(len(data)) > b.maximum {
		return 0, ErrMessageTooLarge
	}

	return b.Buffer.Write(data)
}

// Load reads and validates configured private keys without changing them.
func Load(cfg *config.Config) (*Signers, error) {
	signers := &Signers{
		identities: make(map[string]*identity, len(cfg.OpenPGP.Identities)),
		maximum:    cfg.Server.MaxMessageBytes,
	}

	for _, configured := range cfg.OpenPGP.Identities {
		loaded, err := loadIdentity(cfg, configured)
		if err != nil {
			return nil, fmt.Errorf("openpgp identity %q: %w", configured.Sender, err)
		}

		signers.identities[configured.Sender] = loaded
	}

	return signers, nil
}

func loadIdentity(cfg *config.Config, configured config.OpenPGPIdentity) (*identity, error) {
	entity, err := readEntity(cfg, configured)
	if err != nil {
		return nil, err
	}

	key, ok := entity.SigningKey(time.Now())
	if !ok || key.PrivateKey == nil {
		return nil, errors.New("no valid private signing key")
	}

	encrypted, err := validatePrivateComponents(entity, configured.PassphraseFile != "")
	if err != nil {
		return nil, err
	}

	if encrypted {
		passphrase, err := readPassphrase(cfg, configured.PassphraseFile)
		if err != nil {
			return nil, err
		}

		defer clear(passphrase)

		err = entity.DecryptPrivateKeys(passphrase)
		if err != nil {
			return nil, fmt.Errorf("decrypt signing key: %w", err)
		}
	}

	if _, ok := entity.SigningKey(time.Now()); !ok {
		return nil, errors.New("no currently valid signing key")
	}

	if !hasIdentity(entity, configured.Sender) {
		return nil, errors.New("sender is not present in the key identities")
	}

	err = pgp.DetachSign(bytes.NewBuffer(nil), entity, bytes.NewReader(nil), signingConfig())
	if err != nil {
		return nil, fmt.Errorf("validate signing key: %w", err)
	}

	loaded := &identity{entity: entity, gate: make(chan struct{}, 1)}

	if configured.Autocrypt {
		public, err := publicIdentity(entity, configured.Sender)
		if err != nil {
			return nil, err
		}

		loaded.autocrypt, err = autocryptField(public)
		if err != nil {
			return nil, err
		}
	}

	return loaded, nil
}

func validatePrivateComponents(entity *pgp.Entity, passphraseConfigured bool) (bool, error) {
	keys := make([]*packet.PrivateKey, 0, len(entity.Subkeys)+1)

	keys = append(keys, entity.PrivateKey)

	for i := range entity.Subkeys {
		keys = append(keys, entity.Subkeys[i].PrivateKey)
	}

	var (
		encrypted   bool
		unencrypted bool
	)

	for _, key := range keys {
		if key == nil || key.Dummy() {
			continue
		}

		if !key.Encrypted {
			unencrypted = true

			continue
		}

		encrypted = true
	}

	if encrypted && unencrypted {
		return false, errors.New("private key contains mixed encrypted and unencrypted components")
	}

	if passphraseConfigured != encrypted {
		if encrypted {
			return false, errors.New("signing key is encrypted but passphrase_file is not configured")
		}

		return false, errors.New("passphrase_file is configured but the signing key is not encrypted")
	}

	return encrypted, nil
}

func readPassphrase(cfg *config.Config, path string) ([]byte, error) {
	resolved := cfg.ResolvePath(path)

	if !filepath.IsAbs(path) {
		err := cfg.CheckGeneratedParents(resolved)
		if err != nil {
			return nil, fmt.Errorf("check passphrase file path: %w", err)
		}
	}

	value, err := config.ReadCheckedFile(resolved, true, false, maxPassphraseBytes)
	if err != nil {
		return nil, fmt.Errorf("read passphrase file: %w", err)
	}

	trimmed := bytes.TrimSuffix(value, []byte("\n"))
	trimmed = bytes.TrimSuffix(trimmed, []byte("\r"))

	clear(value[len(trimmed):])

	if len(trimmed) == 0 {
		clear(value)

		return nil, errors.New("passphrase file is empty")
	}

	if bytes.ContainsAny(trimmed, "\r\n\x00") {
		clear(value)

		return nil, errors.New("passphrase file must contain one non-empty line without NUL")
	}

	return trimmed, nil
}

func hasIdentity(entity *pgp.Entity, sender string) bool {
	now := time.Now()

	for _, identity := range entity.Identities {
		if identity.SelfSignature == nil || identity.SelfSignature.SigExpired(now) || identity.Revoked(now) {
			continue
		}

		address, err := mail.ParseAddress(identity.Name)
		if err != nil {
			continue
		}

		if canonicalAddress(address.Address) == sender {
			return true
		}
	}

	return false
}

func canonicalAddress(address string) string {
	at := strings.LastIndexByte(address, '@')
	if at < 0 {
		return address
	}

	return address[:at] + "@" + strings.ToLower(address[at+1:])
}

// Sign wraps data in multipart/signed when sender has a configured identity.
func (s *Signers) Sign(ctx context.Context, sender string, data []byte) ([]byte, bool, error) {
	if s == nil {
		return data, false, nil
	}

	configured := s.identities[sender]
	if configured == nil {
		return data, false, nil
	}

	if err := ctx.Err(); err != nil {
		return nil, false, err
	}

	outer, entity, err := splitMessage(data, len(configured.autocrypt) != 0)
	if err != nil {
		return nil, false, err
	}

	entity, err = canonicalizeEntityContext(ctx, entity, s.maximum, 0)
	if err != nil {
		return nil, false, err
	}

	if !bytes.HasSuffix(entity, []byte("\r\n")) {
		entity = append(entity, '\r', '\n')
	}

	select {
	case configured.gate <- struct{}{}:
		defer func() {
			<-configured.gate
		}()
	case <-ctx.Done():
		return nil, false, ctx.Err()
	}

	var signature bytes.Buffer

	err = pgp.ArmoredDetachSign(contextWriter{ctx: ctx, writer: &signature}, configured.entity, contextReader{ctx: ctx, reader: bytes.NewReader(entity)}, signingConfig())
	if err != nil {
		if ctx.Err() != nil {
			return nil, false, ctx.Err()
		}

		return nil, false, fmt.Errorf("create detached signature: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}

	boundary, err := randomBoundary()
	if err != nil {
		return nil, false, err
	}

	armor := bytes.ReplaceAll(signature.Bytes(), []byte("\n"), []byte("\r\n"))

	outer = append(outer, configured.autocrypt...)

	result := buildSignedMessage(outer, entity, armor, boundary)

	if int64(len(result)) > s.maximum {
		return nil, false, fmt.Errorf("%w: maximum is %d bytes", ErrMessageTooLarge, s.maximum)
	}

	if err := ctx.Err(); err != nil {
		return nil, false, err
	}

	return result, true, nil
}

func signingConfig() *packet.Config {
	return &packet.Config{DefaultHash: crypto.SHA256, MinRSABits: 2048}
}

func randomBoundary() (string, error) {
	var value [24]byte

	_, err := rand.Read(value[:])
	if err != nil {
		return "", fmt.Errorf("generate MIME boundary: %w", err)
	}

	return "outboxd-" + hex.EncodeToString(value[:]), nil
}

func buildSignedMessage(outer, entity, signature []byte, boundary string) []byte {
	var result bytes.Buffer
	result.Grow(len(outer) + len(entity) + len(signature) + 512)

	result.Write(outer)
	result.WriteString("MIME-Version: 1.0\r\n")
	result.WriteString("Content-Type: multipart/signed; protocol=\"application/pgp-signature\"; micalg=pgp-sha256; boundary=\"")
	result.WriteString(boundary)
	result.WriteString("\"\r\n\r\n")
	result.WriteString("This is an OpenPGP/MIME signed message.\r\n\r\n--")
	result.WriteString(boundary)
	result.WriteString("\r\n")
	result.Write(entity)
	result.WriteString("--")
	result.WriteString(boundary)
	result.WriteString("\r\nContent-Type: application/pgp-signature; name=\"signature.asc\"\r\n")
	result.WriteString("Content-Description: OpenPGP digital signature\r\n")
	result.WriteString("Content-Disposition: attachment; filename=\"signature.asc\"\r\n\r\n")
	result.Write(signature)
	result.WriteString("\r\n--")
	result.WriteString(boundary)
	result.WriteString("--\r\n")

	return result.Bytes()
}

func splitMessage(data []byte, replaceAutocrypt bool) ([]byte, []byte, error) {
	headerEnd := bytes.Index(data, []byte("\r\n\r\n"))
	if headerEnd < 0 {
		return nil, nil, errors.New("message has no header/body separator")
	}

	fields, err := headerFields(data[:headerEnd+2])
	if err != nil {
		return nil, nil, err
	}

	var outer, entity bytes.Buffer

	for _, field := range fields {
		name := fieldName(field)
		if strings.HasPrefix(name, "content-") {
			entity.Write(field)
		} else if name != "mime-version" && !(replaceAutocrypt && name == "autocrypt") {
			outer.Write(field)
		}
	}

	entity.WriteString("\r\n")
	entity.Write(data[headerEnd+4:])

	return outer.Bytes(), entity.Bytes(), nil
}

func canonicalizeEntity(data []byte, maximum int64) ([]byte, error) {
	return canonicalizeEntityContext(context.Background(), data, maximum, 0)
}

func canonicalizeEntityContext(ctx context.Context, data []byte, maximum int64, depth int) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if depth > maxMultipartDepth {
		return nil, fmt.Errorf("MIME multipart nesting exceeds maximum depth of %d", maxMultipartDepth)
	}

	if int64(len(data)) > maximum {
		return nil, ErrMessageTooLarge
	}

	headerEnd := bytes.Index(data, []byte("\r\n\r\n"))

	var (
		head []byte
		body []byte
	)

	if headerEnd >= 0 {
		head = data[:headerEnd+2]
		body = data[headerEnd+4:]
	} else if bytes.HasPrefix(data, []byte("\r\n")) {
		body = data[2:]
	} else {
		return nil, errors.New("MIME entity has no header/body separator")
	}

	if !isSevenBit(head) {
		return nil, errors.New("MIME entity headers are not 7-bit safe")
	}

	contentType := headerValue(head, "content-type")
	if contentType == "" {
		contentType = "text/plain; charset=us-ascii"
	}

	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return nil, fmt.Errorf("parse MIME Content-Type: %w", err)
	}

	multipart := strings.HasPrefix(strings.ToLower(mediaType), "multipart/")

	encoding, err := validateTransferEncoding(head, multipart)
	if err != nil {
		return nil, err
	}

	if encoding == "8bit" || encoding == "binary" {
		head, err = replaceHeader(head, "Content-Transfer-Encoding", "7bit")
		if err != nil {
			return nil, err
		}
	}

	if multipart {
		boundary := params["boundary"]
		if boundary == "" {
			return nil, errors.New("multipart MIME entity has no boundary")
		}

		canonicalBody, err := canonicalizeMultipart(ctx, body, boundary, maximum-int64(len(head))-2, depth)
		if err != nil {
			return nil, err
		}

		canonical := joinEntity(head, canonicalBody)

		if !isSevenBit(canonical) {
			return nil, errors.New("multipart MIME preamble or epilogue is not 7-bit safe")
		}

		return canonical, nil
	}

	if isSevenBit(body) {
		return joinEntity(head, body), nil
	}

	if encoding == "base64" || encoding == "quoted-printable" {
		return nil, fmt.Errorf("%s MIME body contains non-ASCII encoded data", encoding)
	}

	if encoding != "" && encoding != "7bit" && encoding != "8bit" && encoding != "binary" {
		return nil, fmt.Errorf("unsupported MIME content-transfer-encoding %q", encoding)
	}

	head, err = replaceHeader(head, "Content-Transfer-Encoding", "quoted-printable")
	if err != nil {
		return nil, err
	}

	var encoded limitedBuffer

	encoded.maximum = maximum - int64(len(head)) - 2
	encoded.ctx = ctx

	writer := quotedprintable.NewWriter(&encoded)

	_, err = writer.Write(body)
	if err != nil {
		return nil, err
	}

	err = writer.Close()
	if err != nil {
		return nil, err
	}

	return joinEntity(head, encoded.Bytes()), nil
}

func validateTransferEncoding(head []byte, multipart bool) (string, error) {
	fields, err := headerFields(head)
	if err != nil {
		return "", err
	}

	var (
		encoding string
		found    bool
	)

	for _, field := range fields {
		if fieldName(field) != "content-transfer-encoding" {
			continue
		}

		if found {
			return "", errors.New("MIME entity has duplicate Content-Transfer-Encoding headers")
		}

		found = true

		colon := bytes.IndexByte(field, ':')
		encoding = strings.ToLower(strings.TrimSpace(strings.ReplaceAll(string(field[colon+1:]), "\r\n", " ")))
	}

	if found && encoding == "" {
		return "", errors.New("MIME Content-Transfer-Encoding is empty")
	}

	if multipart {
		if encoding != "" && encoding != "7bit" && encoding != "8bit" && encoding != "binary" {
			return "", fmt.Errorf("unsupported multipart MIME content-transfer-encoding %q", encoding)
		}
	} else if encoding != "" && encoding != "7bit" && encoding != "8bit" && encoding != "binary" && encoding != "base64" && encoding != "quoted-printable" {
		return "", fmt.Errorf("unsupported MIME content-transfer-encoding %q", encoding)
	}

	return encoding, nil
}

func canonicalizeMultipart(ctx context.Context, body []byte, boundary string, maximum int64, depth int) ([]byte, error) {
	marker := []byte("--" + boundary)

	var result bytes.Buffer

	partStart := -1

	for offset := 0; offset < len(body); {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		lineEnd := bytes.Index(body[offset:], []byte("\r\n"))
		if lineEnd < 0 {
			lineEnd = len(body) - offset
		} else {
			lineEnd += 2
		}

		line := bytes.TrimRight(body[offset:offset+lineEnd], "\r\n \t")
		if bytes.Equal(line, marker) || bytes.Equal(line, append(append([]byte{}, marker...), '-', '-')) {
			if partStart >= 0 {
				part := body[partStart:offset]

				canonical, err := canonicalizeEntityContext(ctx, part, maximum-int64(result.Len()), depth+1)
				if err != nil {
					return nil, err
				}

				err = appendLimited(&result, canonical, maximum)
				if err != nil {
					return nil, err
				}
			} else {
				err := appendLimited(&result, body[:offset], maximum)
				if err != nil {
					return nil, err
				}
			}

			err := appendLimited(&result, body[offset:offset+lineEnd], maximum)
			if err != nil {
				return nil, err
			}

			if bytes.HasSuffix(line, []byte("--")) {
				err = appendLimited(&result, body[offset+lineEnd:], maximum)
				if err != nil {
					return nil, err
				}

				return result.Bytes(), nil
			}

			partStart = offset + lineEnd
		}

		offset += lineEnd
	}

	return nil, errors.New("multipart MIME entity has no closing boundary")
}

func appendLimited(result *bytes.Buffer, data []byte, maximum int64) error {
	if int64(result.Len())+int64(len(data)) > maximum {
		return ErrMessageTooLarge
	}

	result.Write(data)

	return nil
}

func joinEntity(head, body []byte) []byte {
	result := make([]byte, 0, len(head)+2+len(body))

	result = append(result, head...)
	result = append(result, '\r', '\n')
	result = append(result, body...)

	return result
}

func isSevenBit(data []byte) bool {
	for _, value := range data {
		if value >= 0x80 || value == 0 {
			return false
		}
	}

	return true
}

func replaceHeader(head []byte, name, value string) ([]byte, error) {
	fields, err := headerFields(head)
	if err != nil {
		return nil, err
	}

	var result bytes.Buffer

	for _, field := range fields {
		if fieldName(field) != strings.ToLower(name) {
			result.Write(field)
		}
	}

	fmt.Fprintf(&result, "%s: %s\r\n", name, value)

	return result.Bytes(), nil
}

func headerValue(head []byte, wanted string) string {
	fields, _ := headerFields(head)

	for _, field := range fields {
		if fieldName(field) == wanted {
			colon := bytes.IndexByte(field, ':')
			value := strings.ReplaceAll(string(field[colon+1:]), "\r\n", " ")

			return strings.TrimSpace(value)
		}
	}

	return ""
}

func headerFields(head []byte) ([][]byte, error) {
	lines := bytes.SplitAfter(head, []byte("\r\n"))

	fields := make([][]byte, 0, len(lines))

	for _, line := range lines {
		if len(line) == 0 {
			continue
		}

		if line[0] == ' ' || line[0] == '\t' {
			if len(fields) == 0 {
				return nil, errors.New("header starts with a continuation line")
			}

			fields[len(fields)-1] = append(fields[len(fields)-1], line...)

			continue
		}

		if bytes.IndexByte(line, ':') <= 0 {
			return nil, errors.New("malformed MIME header")
		}

		fields = append(fields, append([]byte(nil), line...))
	}

	return fields, nil
}

func fieldName(field []byte) string {
	colon := bytes.IndexByte(field, ':')
	if colon < 0 {
		return ""
	}

	return strings.ToLower(string(field[:colon]))
}

func (r contextReader) Read(data []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}

	return r.reader.Read(data)
}

func (w contextWriter) Write(data []byte) (int, error) {
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}

	return w.writer.Write(data)
}
