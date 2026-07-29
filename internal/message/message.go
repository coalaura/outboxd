package message

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/mail"
	"strconv"
	"strings"
	"time"
)

const (
	maxLineLength  = 998
	maxTraceLength = 128
)

var (
	errEmpty     = errors.New("message is empty")
	errMalformed = errors.New("message header is malformed")
	errNoFrom    = errors.New("message has no From header")
	errManyFrom  = errors.New("message has more than one From header")
	errBinary    = errors.New("message contains a NUL byte")
	errLongLine  = fmt.Errorf("message contains a line longer than %d octets; use quoted-printable or base64", maxLineLength)

	crlf = []byte("\r\n")
)

// Options carries the trace information added to the message.
type Options struct {
	Hostname string
	Helo     string
	Remote   string
	TLS      string
}

// Message is a submission that is ready to be signed and queued.
type Message struct {
	Data []byte
	From string
	ID   string
}

type field struct {
	name  string
	value []byte
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
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	if len(raw) == 0 {
		return nil, errEmpty
	}

	data, err := normalize(raw)
	if err != nil {
		return nil, err
	}

	header, body := split(data)

	fields, err := scan(header)
	if err != nil {
		return nil, err
	}

	present := make(map[string]int, len(fields))

	for _, field := range fields {
		present[field.name]++
	}

	switch present["from"] {
	case 1:
	case 0:
		return nil, errNoFrom
	default:
		return nil, errManyFrom
	}

	var from string

	for _, field := range fields {
		if field.name != "from" {
			continue
		}

		address, err := parser.Parse(field.text())
		if err != nil {
			return nil, fmt.Errorf("invalid From header: %w", err)
		}

		from = address.Address
	}

	identifierDomain := opts.Hostname

	if at := strings.LastIndexByte(from, '@'); at >= 0 && at < len(from)-1 {
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
		opts.Hostname, protocol(opts.TLS), strings.Trim(identifier, "<>"),
		time.Now().Format(time.RFC1123Z),
	)

	if present["date"] == 0 {
		fmt.Fprintf(&out, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	}

	if present["message-id"] == 0 {
		fmt.Fprintf(&out, "Message-ID: %s\r\n", identifier)
	}

	if present["to"] == 0 && present["cc"] == 0 {
		out.WriteString("To: undisclosed-recipients:;\r\n")
	}

	eightBit := !ascii(body)

	if present["content-type"] == 0 && eightBit {
		out.WriteString("Content-Type: text/plain; charset=utf-8\r\n")

		present["content-type"]++
	}

	if present["content-transfer-encoding"] == 0 && eightBit {
		out.WriteString("Content-Transfer-Encoding: 8bit\r\n")
	}

	if present["mime-version"] == 0 && present["content-type"] > 0 {
		out.WriteString("MIME-Version: 1.0\r\n")
	}

	for _, field := range fields {
		// Bcc must never leave the submission server, and Return-Path is set by
		// the receiving MTA from the envelope.
		if field.name == "bcc" || field.name == "return-path" {
			continue
		}

		out.Write(field.value)
	}

	out.Write(crlf)
	out.Write(body)

	return &Message{
		Data: out.Bytes(),
		From: from,
		ID:   identifier,
	}, nil
}

func normalize(raw []byte) ([]byte, error) {
	if bytes.IndexByte(raw, 0) >= 0 {
		return nil, errBinary
	}

	out := make([]byte, 0, len(raw)+len(raw)/16)

	length := 0

	for i := 0; i < len(raw); i++ {
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

func scan(header []byte) ([]field, error) {
	var (
		fields []field
		start  int
	)

	for offset := 0; offset < len(header); {
		end := bytes.Index(header[offset:], crlf)
		if end < 0 {
			return nil, errMalformed
		}

		end += offset + 2
		line := header[offset:end]

		if line[0] == ' ' || line[0] == '\t' {
			if len(fields) == 0 {
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

		name := bytes.TrimRight(line[:colon], " \t")

		for _, char := range name {
			if char < 33 || char > 126 {
				return nil, errMalformed
			}
		}

		start = offset

		fields = append(fields, field{
			name:  strings.ToLower(string(name)),
			value: line,
		})

		offset = end
	}

	return fields, nil
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

func comment(value string) string {
	const limit = 128

	value = strings.Map(func(char rune) rune {
		if char < 33 || char > 126 || char == '(' || char == ')' || char == '\\' {
			return -1
		}

		return char
	}, value)

	if value == "" {
		return "unknown"
	}

	if len(value) > limit {
		return value[:limit]
	}

	return value
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
