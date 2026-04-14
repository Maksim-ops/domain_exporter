package whois

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/domainr/whois"
	"github.com/rs/zerolog/log"
)

const kzRDAPEndpoint = "https://rdap.nic.kz/domain/"

var (
	kzStatusRegex = regexp.MustCompile(`(?im)^Domain status\s*:\s*ok\b`)
	kzDomainRegex = regexp.MustCompile(`(?im)^Domain Name[.\s]*:\s*(\S+)`)
)

// kzAdapter implements custom adapter for .kz domains
type kzAdapter struct{}

type kzRDAPResponse struct {
	Events []kzRDAPEvent `json:"events"`
}

type kzRDAPEvent struct {
	Action string `json:"eventAction"`
	Date   string `json:"eventDate"`
}

func (a *kzAdapter) Prepare(req *whois.Request) error {
	return whois.DefaultAdapter.Prepare(req)
}

func (a *kzAdapter) Text(res *whois.Response) ([]byte, error) {
	text, err := whois.DefaultAdapter.Text(res)
	if err != nil {
		return nil, err
	}

	return enrichKZWhoisResponse(text, time.Now, lookupKZRDAPExpiry), nil
}

func enrichKZWhoisResponse(
	text []byte,
	now func() time.Time,
	lookup func(context.Context, string) (time.Time, error),
) []byte {
	response := string(text)
	if strings.Contains(strings.ToLower(response), "paid-till:") {
		return text
	}

	domain := extractKZDomain(response)
	if domain != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		expiration, err := lookup(ctx, domain)
		if err == nil {
			log.Debug().Str("domain", domain).Time("expires_at", expiration).Msg("resolved .kz expiration via RDAP")
			return []byte(appendKZPaidTill(response, expiration))
		}

		log.Debug().Err(err).Str("domain", domain).Msg("failed to resolve .kz expiration via RDAP")
	} else {
		log.Debug().Msg("failed to extract .kz domain from whois response")
	}

	// Preserve the previous behavior as a last resort for active domains when RDAP is unavailable.
	if kzStatusRegex.MatchString(response) {
		log.Debug().Msg("KZ domain is active based on status")
		expiration := now().AddDate(1, 0, 0)
		return []byte(appendKZPaidTill(response, expiration))
	}

	log.Debug().Msg("KZ domain is not active or status not found")
	return text
}

func extractKZDomain(response string) string {
	match := kzDomainRegex.FindStringSubmatch(response)
	if len(match) < 2 {
		return ""
	}

	return strings.ToLower(strings.TrimSpace(match[1]))
}

func appendKZPaidTill(response string, expiration time.Time) string {
	return response + fmt.Sprintf("\npaid-till: %s", expiration.UTC().Format(time.RFC3339))
}

func lookupKZRDAPExpiry(ctx context.Context, domain string) (time.Time, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, kzRDAPEndpoint+url.PathEscape(domain), nil)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to create .kz RDAP request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to do .kz RDAP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return time.Time{}, fmt.Errorf("unexpected .kz RDAP status: %s", resp.Status)
	}

	var body kzRDAPResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return time.Time{}, fmt.Errorf("failed to decode .kz RDAP response: %w", err)
	}

	for _, event := range body.Events {
		if event.Action != "expiration" {
			continue
		}

		expiration, err := time.Parse(time.RFC3339, event.Date)
		if err != nil {
			return time.Time{}, fmt.Errorf("failed to parse .kz RDAP expiration %q: %w", event.Date, err)
		}

		return expiration, nil
	}

	return time.Time{}, fmt.Errorf("no expiration event in .kz RDAP response for %s", domain)
}

func init() {
	whois.BindAdapter(
		&kzAdapter{},
		"whois.nic.kz",
	)
}
