package check

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/coalaura/outboxd/internal/config"
)

func checkDMARC(ctx context.Context, r Resolver, cfg *config.Config) []Result {
	name := "_dmarc." + strings.TrimSuffix(cfg.Server.Domain, ".")
	checkName := "dmarc"

	txts, err := r.LookupTXT(ctx, name)
	if err != nil {
		return []Result{{
			Name:    checkName,
			Level:   Fail,
			Message: fmt.Sprintf("TXT lookup %s: %v", name, err),
		}}
	}

	var found []string

	for _, t := range txts {
		tt := strings.TrimSpace(t)

		first, _, _ := strings.Cut(tt, ";")
		if strings.EqualFold(strings.TrimSpace(first), "v=DMARC1") {
			found = append(found, tt)
		}
	}

	if len(found) == 0 {
		return []Result{{
			Name:    checkName,
			Level:   Fail,
			Message: fmt.Sprintf("no DMARC TXT at %s", name),
		}}
	}

	if len(found) > 1 {
		return []Result{{
			Name:    checkName,
			Level:   Fail,
			Message: fmt.Sprintf("multiple DMARC TXT at %s", name),
		}}
	}

	tags, err := parseDMARCTags(found[0])
	if err != nil {
		return []Result{{
			Name:    checkName,
			Level:   Fail,
			Message: fmt.Sprintf("DMARC record invalid: %v", err),
		}}
	}

	p := strings.ToLower(tags["p"])

	switch p {
	case "none", "quarantine", "reject":
	case "":
		return []Result{{
			Name:    checkName,
			Level:   Fail,
			Message: "DMARC record missing p=",
		}}
	default:
		return []Result{{
			Name:    checkName,
			Level:   Fail,
			Message: fmt.Sprintf("DMARC p=%q is not none/quarantine/reject", p),
		}}
	}

	want := strings.ToLower(cfg.DNS.DMARC)
	if want == "" {
		want = "none"
	}

	level := Pass
	msg := fmt.Sprintf("DMARC p=%s", p)

	if p != want {
		level = Fail
		msg = fmt.Sprintf("DMARC p=%s does not match config dmarc_policy=%s", p, want)
	} else if p == "none" {
		level = Warn
		msg = "DMARC p=none (monitor only); stage to quarantine/reject after verifying alignment"
	}

	rua := tags["rua"]
	if rua == "" {
		if level == Pass {
			level = Warn
		}

		msg += "; no rua= (no aggregate reports)"
	} else {
		err = config.ValidateDMARCReportURIList(rua)
		if err != nil {
			return []Result{{
				Name:    checkName,
				Level:   Fail,
				Message: fmt.Sprintf("DMARC rua invalid: %v", err),
			}}
		}
	}

	return []Result{{
		Name:    checkName,
		Level:   level,
		Message: msg,
	}}
}

func parseDMARCTags(record string) (map[string]string, error) {
	parts := strings.Split(record, ";")
	tags := make(map[string]string, len(parts))

	for i, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			if i == len(parts)-1 {
				continue
			}

			return nil, errors.New("empty tag")
		}

		key, value, ok := strings.Cut(part, "=")
		key, value = strings.ToLower(strings.TrimSpace(key)), strings.TrimSpace(value)

		if !ok || key == "" || value == "" || !asciiLetters(key) {
			return nil, fmt.Errorf("malformed tag %q", part)
		}

		_, duplicate := tags[key]
		if duplicate {
			return nil, fmt.Errorf("duplicate %s tag", key)
		}

		tags[key] = value
	}

	if !strings.EqualFold(tags["v"], "DMARC1") {
		return nil, errors.New("first tag must be exactly v=DMARC1")
	}

	return tags, nil
}

func asciiLetters(value string) bool {
	for _, char := range value {
		if char < 'a' || char > 'z' {
			return false
		}
	}

	return value != ""
}
