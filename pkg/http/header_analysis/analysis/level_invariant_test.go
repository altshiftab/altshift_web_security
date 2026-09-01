package analysis

import (
	"net/http"
	"testing"

	"github.com/altshiftab/utils_go/pkg/sarif"
)

// validLevels are the only levels SARIF defines. A rule whose severity is
// dynamic carries an internal placeholder until the analyzer that raised it
// picks a level, and that placeholder is not one of these - so a path that
// forgets to resolve it would put an invalid value on the wire.
var validLevels = map[sarif.Level]struct{}{
	"":                 {},
	sarif.LevelNone:    {},
	sarif.LevelNote:    {},
	sarif.LevelWarning: {},
	sarif.LevelError:   {},
}

func TestAnalyzeHeadersEmitsOnlyValidLevels(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		header http.Header
	}{
		{
			name:   "insecure scheme in default-src",
			header: http.Header{"Content-Security-Policy": []string{"default-src 'self' http://evil.test; base-uri 'self'; form-action 'self'; frame-ancestors 'self'"}},
		},
		{
			name:   "wildcard host",
			header: http.Header{"Content-Security-Policy": []string{"default-src *; base-uri 'self'; form-action 'self'; frame-ancestors 'self'"}},
		},
		{
			name:   "unsafe-inline on script-src",
			header: http.Header{"Content-Security-Policy": []string{"script-src 'unsafe-inline'; default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'self'"}},
		},
		{
			name:   "unsafe-inline on a directive it has no effect on",
			header: http.Header{"Content-Security-Policy": []string{"img-src 'unsafe-inline'; default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'self'"}},
		},
		{
			name:   "data scheme in a sensitive directive",
			header: http.Header{"Content-Security-Policy": []string{"script-src data:; default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'self'"}},
		},
		{
			name:   "loopback host",
			header: http.Header{"Content-Security-Policy": []string{"default-src 'self' http://127.0.0.1; base-uri 'self'; form-action 'self'; frame-ancestors 'self'"}},
		},
		{
			name:   "no scheme on a host source",
			header: http.Header{"Content-Security-Policy": []string{"default-src example.test; base-uri 'self'; form-action 'self'; frame-ancestors 'self'"}},
		},
		{
			name:   "unsafe-eval",
			header: http.Header{"Content-Security-Policy": []string{"script-src 'unsafe-eval'; default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'self'"}},
		},
		{
			name:   "a bare response with no security headers at all",
			header: http.Header{"Content-Type": []string{"text/html"}},
		},
		{
			name: "every analysed header present",
			header: http.Header{
				"Content-Security-Policy":      []string{"default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'self'"},
				"Strict-Transport-Security":    []string{"max-age=31536000; includeSubDomains; preload"},
				"X-Content-Type-Options":       []string{"nosniff"},
				"X-Frame-Options":              []string{"DENY"},
				"Referrer-Policy":              []string{"unsafe-url"},
				"Cross-Origin-Opener-Policy":   []string{"unsafe-none"},
				"Cross-Origin-Embedder-Policy": []string{"unsafe-none"},
				"Cross-Origin-Resource-Policy": []string{"cross-origin"},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			run, err := AnalyzeHeaders(testCase.header)
			if err != nil {
				t.Fatalf("AnalyzeHeaders: %v", err)
			}
			if run == nil {
				t.Fatal("expected a run, got nil")
			}

			for _, result := range run.Results {
				if result == nil {
					continue
				}
				if _, ok := validLevels[result.Level]; !ok {
					t.Errorf("rule %q emitted level %q, which SARIF does not define",
						result.RuleId, result.Level)
				}
			}
		})
	}
}

// A malformed HSTS header must be reported rather than crash: the parser it
// delegates to can return a nil policy with no error.
func TestAnalyzeHeadersToleratesMalformedStrictTransportSecurity(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name  string
		value string
	}{
		{name: "empty directive", value: ";"},
		{name: "unknown directive only", value: "not-a-directive"},
		{name: "max-age without a value", value: "max-age"},
		{name: "trailing separator", value: "max-age=31536000;"},
		{name: "garbage", value: "!!!"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			run, err := AnalyzeHeaders(http.Header{"Strict-Transport-Security": []string{testCase.value}})
			if err != nil {
				t.Fatalf("AnalyzeHeaders: %v", err)
			}
			if run == nil {
				t.Fatal("expected a run, got nil")
			}
		})
	}
}
