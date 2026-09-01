// Package retrieval fetches the security.txt a host serves, and records enough about
// the fetching for the analysis to report on it.
//
// RFC 9116 puts requirements on how the file is served as well as on what it says --
// the well-known path, the https scheme, the content type -- so what a check needs is
// not the file's contents but the whole transaction.
package retrieval

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/http/types/fetch_config"
	"github.com/altshiftab/utils_go/pkg/http/types/security_txt"
	altshiftHttpUtils "github.com/altshiftab/utils_go/pkg/http/utils"
)

const (
	// WellKnownPath is where RFC 9116 section 3 says the file MUST be.
	WellKnownPath = "/.well-known/security.txt"
	// LegacyPath is where it was put before the RFC, and where section 3 allows a
	// copy to remain for compatibility. A file found only here is in the wrong
	// place.
	LegacyPath = "/security.txt"
	// MaximumSize bounds what is read. A security.txt is a few hundred bytes, and a
	// host that answers the path with something enormous is not serving one.
	MaximumSize = 1 << 20
)

// Attempt is one URL tried and what came back.
type Attempt struct {
	// Url is what was requested.
	Url string
	// WellKnown says whether this was the path RFC 9116 requires.
	WellKnown bool
	// FinalUrl is where the request ended after any redirects, which is what
	// decides whether the file was served over https.
	FinalUrl    string
	StatusCode  int
	ContentType string
	Body        []byte
	// Error is set when the request could not be made at all.
	Error string
}

// Ok reports whether this attempt found a file.
func (attempt *Attempt) Ok() bool {
	return attempt != nil && attempt.Error == "" && attempt.StatusCode == http.StatusOK
}

// Retrieval is everything one host's security.txt lookup found.
type Retrieval struct {
	Host string
	// Attempts are the URLs tried, in order.
	Attempts []*Attempt
	// Found is the attempt whose file is the one to read, and is nil when the host
	// serves none.
	Found *Attempt
	// Parsed is the file, when one was found and could be read.
	Parsed *security_txt.Parsed
	// ParseError says why the file could not be read, when it could not.
	ParseError string
	// Now is when the retrieval happened, which is what an Expires is held against.
	// It is carried rather than read from the clock at analysis time so that a
	// stored retrieval is analysed against the moment it was made.
	Now time.Time
}

// Settings bound a retrieval.
type Settings struct {
	Timeout time.Duration
	// Insecure proceeds even though the server's certificate does not verify. What
	// the certificate says is a separate question from what the file says.
	Insecure bool
	Client   *http.Client
}

// DefaultSettings are what a caller gets for not choosing.
func DefaultSettings() *Settings {
	return &Settings{Timeout: 10 * time.Second}
}

// Retrieve looks for a host's security.txt, at the well-known path and then at the
// legacy one.
//
// It returns an error only when it was given nothing to look at. A host that serves
// no security.txt is not a failure; it is the finding.
func Retrieve(ctx context.Context, host string, settings *Settings) (*Retrieval, error) {
	if host == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("host"))
	}

	if settings == nil {
		settings = DefaultSettings()
	}

	client := settings.Client
	if client == nil {
		client = &http.Client{Timeout: settings.Timeout}

		if settings.Insecure {
			//nolint:gosec // Skipping verification is what Insecure asks for. Whether
			// the certificate verifies is a question the TLS checks answer; refusing
			// to read the security.txt of a host whose certificate has expired would
			// withhold one finding for the sake of another already reported.
			client.Transport = &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			}
		}
	}

	retrieval := &Retrieval{Host: host, Now: time.Now()}

	// The well-known path first: section 3 requires it there, and requires it to be
	// the one used when a file is in both places.
	for _, path := range []string{WellKnownPath, LegacyPath} {
		attempt := fetch(ctx, client, host, path)
		retrieval.Attempts = append(retrieval.Attempts, attempt)

		if !attempt.Ok() {
			continue
		}

		retrieval.Found = attempt

		parsed, err := security_txt.Parse(attempt.Body)
		if err != nil {
			retrieval.ParseError = err.Error()

			break
		}

		retrieval.Parsed = parsed

		break
	}

	return retrieval, nil
}

func fetch(ctx context.Context, client *http.Client, host string, path string) *Attempt {
	target := (&url.URL{Scheme: "https", Host: host, Path: path}).String()

	attempt := &Attempt{Url: target, WellKnown: path == WellKnownPath}

	// A 404 is the ordinary answer at both these paths and is what sends the
	// lookup on to the next one, so the status must come back as a fact rather
	// than as an error.
	response, body, err := altshiftHttpUtils.Fetch(
		ctx,
		target,
		fetch_config.WithHttpClient(client),
		fetch_config.WithSkipErrorOnStatus(true),
	)
	if err != nil {
		attempt.Error = fmt.Sprintf("fetch: %v", err)

		return attempt
	}

	if response == nil {
		attempt.Error = "the fetch returned no response"

		return attempt
	}

	attempt.StatusCode = response.StatusCode
	attempt.ContentType = response.Header.Get("Content-Type")
	attempt.FinalUrl = target

	if response.Request != nil && response.Request.URL != nil {
		attempt.FinalUrl = response.Request.URL.String()
	}

	// A security.txt is a few hundred bytes. What arrives beyond MaximumSize is
	// not one, and is cut here rather than parsed.
	if len(body) > MaximumSize {
		body = body[:MaximumSize]
	}

	attempt.Body = body

	return attempt
}

// ServedOverHttps reports whether the file that was found ended up being served over
// https, which RFC 9116 section 3 requires. A redirect to http is what this catches.
func (retrieval *Retrieval) ServedOverHttps() bool {
	if retrieval == nil || retrieval.Found == nil {
		return false
	}

	parsed, err := url.Parse(retrieval.Found.FinalUrl)
	if err != nil {
		return false
	}

	return strings.EqualFold(parsed.Scheme, "https")
}

// ContentTypeIsPlainUtf8 reports whether the file was served as RFC 9116 section 3
// requires: text/plain, with the charset parameter set to utf-8.
func (retrieval *Retrieval) ContentTypeIsPlainUtf8() bool {
	if retrieval == nil || retrieval.Found == nil {
		return false
	}

	mediaType, parameters, found := strings.Cut(retrieval.Found.ContentType, ";")
	if !strings.EqualFold(strings.TrimSpace(mediaType), "text/plain") {
		return false
	}

	if !found {
		return false
	}

	for _, parameter := range strings.Split(parameters, ";") {
		name, value, found := strings.Cut(parameter, "=")
		if !found {
			continue
		}

		if !strings.EqualFold(strings.TrimSpace(name), "charset") {
			continue
		}

		return strings.EqualFold(strings.Trim(strings.TrimSpace(value), "\""), "utf-8")
	}

	return false
}
