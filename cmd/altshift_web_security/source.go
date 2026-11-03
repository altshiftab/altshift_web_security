package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"time"

	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
)

// normalizeUrl gives a bare host the scheme it was going to be given anyway. A site is asked about
// over https unless the caller says otherwise, http being the thing the analysis reports on rather
// than a way to reach a site.
func normalizeUrl(target string) string {
	if target == "" {
		return ""
	}

	if strings.Contains(target, "://") {
		return target
	}

	return "https://" + target
}

// parseRequestHeaders turns the "Name: value" arguments of -H into a header. A name may be repeated,
// which sends the field twice rather than replacing what came before.
func parseRequestHeaders(values []string) (http.Header, error) {
	if len(values) == 0 {
		return nil, nil
	}

	header := make(http.Header, len(values))

	for _, value := range values {
		name, fieldValue, found := strings.Cut(value, ":")
		if !found {
			return nil, altshiftErrors.NewWithTrace(
				fmt.Errorf("%w: no colon separates the name from the value", altshiftErrors.ErrParseError),
				value,
			)
		}

		name = strings.TrimSpace(name)
		if name == "" {
			return nil, altshiftErrors.NewWithTrace(
				fmt.Errorf("%w: the name is empty", altshiftErrors.ErrParseError),
				value,
			)
		}

		header.Add(name, strings.TrimSpace(fieldValue))
	}

	return header, nil
}

// fetch asks the site for a response and returns the headers it came back with.
func fetch(
	ctx context.Context,
	target string,
	settings *headersSettings,
	requestHeader http.Header,
) (http.Header, error) {
	if settings == nil {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("settings"))
	}

	request, err := http.NewRequestWithContext(ctx, settings.method, target, nil)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("http new request with context: %w", err),
			settings.method,
			target,
		)
	}

	for name, values := range requestHeader {
		for _, value := range values {
			request.Header.Add(name, value)
		}
	}

	transport := &http.Transport{
		// The headers the server sent are the whole subject, so nothing may rewrite them on the way
		// in. Left on, the transport asks for gzip of its own accord and then strips Content-Encoding
		// and Content-Length from what it hands back once it has decompressed -- and those are two of
		// the three fields that decide whether a response is treated as carrying a document at all.
		// Off, a caller who wants to see a compressed response asks for one with -H.
		DisableCompression: true,
	}

	if settings.insecure {
		//nolint:gosec // Skipping verification is what --insecure asks for: a certificate that does
		// not verify is a finding about the site, not a reason to be unable to look at its headers.
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	client := &http.Client{Transport: transport}
	if settings.timeoutSeconds > 0 {
		client.Timeout = time.Duration(settings.timeoutSeconds) * time.Second
	}

	if settings.noFollow {
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}

	response, err := client.Do(request)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("client do: %w", err), target)
	}
	if response == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("response"), target)
	}
	defer func() { _ = response.Body.Close() }()

	return response.Header, nil
}
