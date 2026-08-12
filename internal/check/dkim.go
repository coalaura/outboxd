package check

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/coalaura/outboxd/internal/config"
)

func checkDKIM(ctx context.Context, r Resolver, cfg *config.Config, key *DKIMKey) []Result {
	selector := cfg.DKIM.Selector
	if key != nil && key.Selector != "" {
		selector = key.Selector
	}

	name := fmt.Sprintf("%s._domainkey.%s", selector, strings.TrimSuffix(cfg.Server.Domain, "."))
	checkName := "dkim"

	txts, err := r.LookupTXT(ctx, name)
	if err != nil {
		return []Result{{
			Name:    checkName,
			Level:   Fail,
			Message: fmt.Sprintf("TXT lookup %s: %v", name, err),
		}}
	}

	var dkim []string

	for _, t := range txts {
		tt := strings.TrimSpace(collapseSpaces(t))
		if strings.HasPrefix(strings.ToLower(tt), "v=dkim1") {
			dkim = append(dkim, tt)
		}
	}

	if len(dkim) == 0 {
		return []Result{{
			Name:    checkName,
			Level:   Fail,
			Message: fmt.Sprintf("no DKIM TXT at %s", name),
		}}
	}

	if len(dkim) > 1 {
		return []Result{{
			Name:    checkName,
			Level:   Fail,
			Message: fmt.Sprintf("multiple DKIM TXT at %s", name),
		}}
	}

	if key == nil || key.PublicKey == "" {
		return []Result{{
			Name:    checkName,
			Level:   Warn,
			Message: fmt.Sprintf("DKIM TXT present at %s (local key not provided for comparison)", name),
		}}
	}

	pub, ok := dkimP(dkim[0])
	if !ok {
		return []Result{{
			Name:    checkName,
			Level:   Fail,
			Message: fmt.Sprintf("DKIM TXT at %s missing p=", name),
		}}
	}

	// Compare base64 payloads (ignore padding differences).
	if normalizeB64(pub) != normalizeB64(key.PublicKey) {
		return []Result{{
			Name:    checkName,
			Level:   Fail,
			Message: fmt.Sprintf("DKIM p= at %s does not match the loaded private key", name),
		}}
	}

	return []Result{{
		Name:    checkName,
		Level:   Pass,
		Message: fmt.Sprintf("DKIM selector %s matches loaded key", selector),
	}}
}

func collapseSpaces(s string) string {
	return strings.Join(strings.Fields(s), "")
}

func dkimP(record string) (string, bool) {
	tags := parseTags(record)

	p, ok := tags["p"]
	return p, ok
}

func parseTags(record string) map[string]string {
	out := make(map[string]string)

	for part := range strings.SplitSeq(record, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}

		out[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
	}

	return out
}

func normalizeB64(s string) string {
	s = collapseSpaces(s)

	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(s)
		if err != nil {
			return s
		}
	}

	return base64.StdEncoding.EncodeToString(raw)
}
