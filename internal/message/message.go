package message

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/mail"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/coalaura/outboxd/internal/mailbox"
)

const (
	maxLineLength   = 998
	maxTraceLength  = 128
	maxHeaderBytes  = 1 << 20
	maxHeaderFields = 1000
)

var (
	errEmpty      = errors.New("message is empty")
	errMalformed  = errors.New("message header is malformed")
	errNoFrom     = errors.New("message has no From header")
	errManyFrom   = errors.New("message has more than one From header")
	errBinary     = errors.New("message contains a NUL byte")
	errLongLine   = fmt.Errorf("message contains a line longer than %d octets; use quoted-printable or base64", maxLineLength)
	errOversized  = errors.New("message exceeds size limit")
	errHeaderSize = fmt.Errorf("message header exceeds %d octets", maxHeaderBytes)
	errFieldCount = fmt.Errorf("message header exceeds %d fields", maxHeaderFields)
	errResent     = errors.New("resent headers are not supported")

	crlf = []byte("\r\n")

	// ErrOversized is returned when the submission exceeds Options.MaxBytes.
	ErrOversized = errOversized
)

// Options carries the trace information added to the message.
type Options struct {
	Hostname string
	Helo     string
	Remote   string
	TLS      string

	// MaxBytes limits the raw submission size. Zero means no limit here
	// (the SMTP layer may still enforce MaxMessageBytes).
	MaxBytes int64
}

// Message is a submission that is ready to be signed and queued.
type Message struct {
	Data   []byte
	From   string
	Sender string
	ID     string

	// NeedsUTF8 is true when envelope-bound header material uses raw UTF-8
	// (internationalized addresses or non-ASCII header bytes not in encoded-words
	// alone). Delivery must advertise SMTPUTF8 when this is set.
	NeedsUTF8 bool

	// EightBit is true when the body contains octets with the high bit set.
	EightBit bool
}

type field struct {
	name  string
	value []byte
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

var parser = mail.AddressParser{WordDecoder: new(mime.WordDecoder)}

func (f field) text() string {
	_, body, _ := bytes.Cut(f.value, []byte(":"))

	// Unfolding only has to drop the CRLF; the folding whitespace stays.
	return string(bytes.TrimSpace(bytes.ReplaceAll(body, crlf, nil)))
}

// Prepare normalizes a submitted message and adds the headers a receiving MTA
// expects to see.
func Prepare(r io.Reader, opts Options) (*Message, error) {
	return PrepareContext(context.Background(), r, opts)
}

// PrepareContext is Prepare with cancellation propagated through input and
// CPU-bound normalization/parsing stages.
func PrepareContext(ctx context.Context, r io.Reader, opts Options) (*Message, error) {
	var (
		raw []byte
		err error
	)

	if opts.MaxBytes > 0 {
		raw, err = io.ReadAll(io.LimitReader(contextReader{ctx: ctx, reader: r}, opts.MaxBytes+1))
		if err != nil {
			return nil, err
		}

		if int64(len(raw)) > opts.MaxBytes {
			return nil, errOversized
		}
	} else {
		raw, err = io.ReadAll(contextReader{ctx: ctx, reader: r})
		if err != nil {
			return nil, err
		}
	}

	if len(raw) == 0 {
		return nil, errEmpty
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	data, err := normalize(ctx, raw)
	if err != nil {
		return nil, err
	}

	header, body := split(data)
	if len(header) > maxHeaderBytes {
		return nil, errHeaderSize
	}

	fields, err := scan(ctx, header)
	if err != nil {
		return nil, err
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	present := make(map[string]int, len(fields))

	for _, field := range fields {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		present[field.name]++
	}

	switch present["from"] {
	case 1:
	case 0:
		return nil, errNoFrom
	default:
		return nil, errManyFrom
	}

	var (
		from      string
		sender    string
		needsUTF8 bool
	)

	for _, field := range fields {
		if strings.HasPrefix(field.name, "resent-") {
			return nil, errResent
		}

		if fieldHasHighBit(field.value) {
			if !utf8.Valid(field.value) {
				return nil, errors.New("message header contains invalid UTF-8")
			}

			needsUTF8 = true
		}

		if field.name != "from" && field.name != "sender" {
			continue
		}

		address, err := parser.Parse(field.text())
		if err != nil {
			return nil, fmt.Errorf("invalid %s header: %w", canonicalHeader(field.name), err)
		}

		// Preserve local-part case; only the domain is case-insensitive.
		originator := preserveLocalPartCase(field.text(), address.Address)
		if err := mailbox.ValidateAddress(originator); err != nil {
			return nil, fmt.Errorf("invalid %s header: %w", canonicalHeader(field.name), err)
		}

		if needsUTF8Addr(originator) {
			needsUTF8 = true
		}

		if field.name == "from" {
			from = originator
		} else {
			if sender != "" {
				return nil, errors.New("message has more than one Sender header")
			}

			sender = originator
		}
	}

	identifierDomain := opts.Hostname

	at := strings.LastIndexByte(from, '@')
	if at >= 0 && at < len(from)-1 {
		identifierDomain = from[at+1:]
	}

	identifier := messageID(identifierDomain)

	var out bytes.Buffer
	out.Grow(len(data) + 512)

	fmt.Fprintf(&out, "Received: from %s", traceValue(opts.Helo))

	if opts.Remote != "" {
		fmt.Fprintf(&out, " (%s)", traceValue(opts.Remote))
	}

	fmt.Fprintf(
		&out,
		"\r\n\tby %s with %s id %s;\r\n\t%s\r\n",
		opts.Hostname,
		protocol(opts.TLS),
		strings.Trim(identifier, "<>"),
		time.Now().Format(time.RFC1123Z),
	)

	// Date: inject when missing or unusable.
	dateField, ok := firstField(fields, "date")
	if !ok || !validDate(dateField.text()) {
		fmt.Fprintf(&out, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))

		present["date"] = 1
	}

	// Message-ID: inject when missing or unusable.
	msgID := identifier

	idField, ok := firstField(fields, "message-id")
	if ok && validMessageID(idField.text()) {
		msgID = strings.TrimSpace(idField.text())
	} else {
		fmt.Fprintf(&out, "Message-ID: %s\r\n", identifier)

		present["message-id"] = 1
	}

	if present["to"] == 0 && present["cc"] == 0 {
		out.WriteString("To: undisclosed-recipients:;\r\n")
	}

	eightBit := !ascii(body)
	bodyUTF8 := eightBit && utf8.Valid(body)

	if present["content-type"] == 0 && bodyUTF8 {
		out.WriteString("Content-Type: text/plain; charset=utf-8\r\n")

		present["content-type"]++
	}

	if present["content-transfer-encoding"] == 0 && eightBit {
		out.WriteString("Content-Transfer-Encoding: 8bit\r\n")
	}

	if present["mime-version"] == 0 && (present["content-type"] > 0 || eightBit) {
		out.WriteString("MIME-Version: 1.0\r\n")
	}

	var (
		rewriteDate  bool
		rewriteMsgID bool
	)

	df, ok := firstField(fields, "date")
	if ok && !validDate(df.text()) {
		rewriteDate = true
	}

	mf, ok := firstField(fields, "message-id")
	if ok && !validMessageID(mf.text()) {
		rewriteMsgID = true
	}

	for _, field := range fields {
		// Bcc / Resent-Bcc must never leave the submission server.
		// Return-Path is set by the receiving MTA from the envelope.
		switch field.name {
		case "bcc", "resent-bcc", "return-path":
			continue
		case "date":
			if rewriteDate {
				continue
			}
		case "message-id":
			if rewriteMsgID {
				continue
			}
		}

		out.Write(field.value)
	}

	out.Write(crlf)
	out.Write(body)

	return &Message{
		Data:      out.Bytes(),
		From:      from,
		Sender:    sender,
		ID:        msgID,
		NeedsUTF8: needsUTF8,
		EightBit:  eightBit,
	}, nil
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}

	return r.reader.Read(p)
}

func firstField(fields []field, name string) (field, bool) {
	for _, f := range fields {
		if f.name == name {
			return f, true
		}
	}

	return field{}, false
}

func validDate(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}

	_, err := mail.ParseDate(value)
	return err == nil
}

func validMessageID(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) < 5 || value[0] != '<' || value[len(value)-1] != '>' {
		return false
	}

	inner := value[1 : len(value)-1]

	at := strings.LastIndexByte(inner, '@')
	if at <= 0 || at == len(inner)-1 {
		return false
	}

	for i := 0; i < len(inner); i++ {
		c := inner[i]
		if c <= 32 || c >= 127 {
			return false
		}
	}

	return true
}

// preserveLocalPartCase returns addr with the local-part casing taken from the
// original header text when the addresses match case-insensitively.
func preserveLocalPartCase(headerText, parsed string) string {
	// parsed comes from net/mail with a lowercased domain.
	at := strings.LastIndexByte(parsed, '@')
	if at < 0 {
		return parsed
	}

	// Pull the raw addr-spec from the header if present.
	raw := headerText

	i := strings.LastIndex(headerText, "<")
	if i >= 0 {
		j := strings.LastIndex(headerText, ">")
		if j > i {
			raw = headerText[i+1 : j]
		}
	}

	raw = strings.TrimSpace(raw)

	rat := strings.LastIndexByte(raw, '@')
	if rat < 0 {
		return parsed
	}

	if !strings.EqualFold(raw, parsed) && !strings.EqualFold(raw[rat+1:], parsed[at+1:]) {
		return parsed
	}

	// Domain lowercased, local-part as written.
	return raw[:rat] + "@" + strings.ToLower(raw[rat+1:])
}

func needsUTF8Addr(addr string) bool {
	for i := 0; i < len(addr); i++ {
		if addr[i] >= 0x80 {
			return true
		}
	}

	return !utf8.ValidString(addr)
}

func fieldHasHighBit(value []byte) bool {
	for _, b := range value {
		if b >= 0x80 {
			return true
		}
	}

	return false
}

func normalize(ctx context.Context, raw []byte) ([]byte, error) {
	if bytes.IndexByte(raw, 0) >= 0 {
		return nil, errBinary
	}

	out := make([]byte, 0, len(raw)+len(raw)/16)

	length := 0

	for i := 0; i < len(raw); i++ {
		if i&4095 == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}

		switch raw[i] {
		case '\r':
			if i+1 < len(raw) && raw[i+1] == '\n' {
				i++
			}

			out = append(out, crlf...)

			length = 0
		case '\n':
			out = append(out, crlf...)

			length = 0
		default:
			out = append(out, raw[i])

			length++
			if length > maxLineLength {
				return nil, errLongLine
			}
		}
	}

	if !bytes.HasSuffix(out, crlf) {
		out = append(out, crlf...)
	}

	return out, nil
}

func split(data []byte) (header, body []byte) {
	separator := bytes.Index(data, []byte("\r\n\r\n"))
	if separator < 0 {
		return data, nil
	}

	return data[:separator+2], data[separator+4:]
}

func scan(ctx context.Context, header []byte) ([]field, error) {
	var (
		fields []field
		start  int
	)

	for offset := 0; offset < len(header); {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		end := bytes.Index(header[offset:], crlf)
		if end < 0 {
			return nil, errMalformed
		}

		end += offset + 2
		line := header[offset:end]

		// Folded continuation: must start with SP/HTAB and follow a field.
		if line[0] == ' ' || line[0] == '\t' {
			if len(fields) == 0 {
				return nil, errMalformed
			}

			// Bare folding whitespace line (CRLF SP CRLF) is malformed.
			if len(bytes.TrimSpace(line[:len(line)-2])) == 0 {
				return nil, errMalformed
			}

			// Prohibit NUL already handled; reject other C0 controls in folds.
			if containsHeaderControls(line[:len(line)-2]) {
				return nil, errMalformed
			}

			fields[len(fields)-1].value = header[start:end]
			offset = end

			continue
		}

		colon := bytes.IndexByte(line, ':')
		if colon <= 0 {
			return nil, errMalformed
		}

		name := line[:colon]

		// Field-name is 1*ftext (RFC 5322): %d33-57 / %d59-126 (no colon, no space).
		if !validFieldName(name) {
			return nil, errMalformed
		}

		// Header field body (before CRLF) must not contain bare CR/LF or C0 controls.
		body := line[colon+1 : len(line)-2]
		if containsHeaderControls(body) {
			return nil, errMalformed
		}

		start = offset
		if len(fields) >= maxHeaderFields {
			return nil, errFieldCount
		}

		fields = append(fields, field{
			name:  strings.ToLower(string(name)),
			value: line,
		})

		offset = end
	}

	return fields, nil
}

func canonicalHeader(name string) string {
	if name == "sender" {
		return "Sender"
	}

	return "From"
}

func validFieldName(name []byte) bool {
	if len(name) == 0 {
		return false
	}

	for _, c := range name {
		// ftext = %d33-57 / %d59-126
		if c < 33 || c > 126 || c == ':' {
			return false
		}
	}

	return true
}

func containsHeaderControls(b []byte) bool {
	for _, c := range b {
		// Allow HTAB (9) and SP (32). Reject other C0 and DEL.
		if c == 127 || (c < 32 && c != '\t') {
			return true
		}
	}

	return false
}

func traceValue(value string) string {
	var builder strings.Builder
	builder.Grow(min(len(value), maxTraceLength))

	for _, char := range value {
		if builder.Len() >= maxTraceLength {
			break
		}

		if char < 33 || char > 126 || char == '(' || char == ')' || char == '\\' {
			continue
		}

		builder.WriteRune(char)
	}

	if builder.Len() == 0 {
		return "unknown"
	}

	return builder.String()
}

func messageID(hostname string) string {
	return fmt.Sprintf(
		"<%s.%s@%s>",
		strconv.FormatInt(time.Now().Unix(), 36),
		strings.ToLower(rand.Text()),
		hostname,
	)
}

func protocol(state string) string {
	if state == "" {
		return "ESMTPA"
	}

	return "ESMTPSA"
}

func ascii(body []byte) bool {
	for _, char := range body {
		if char > 127 {
			return false
		}
	}

	return true
}
