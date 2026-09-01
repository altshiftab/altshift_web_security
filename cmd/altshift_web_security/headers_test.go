package main

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/altshiftab/utils_go/pkg/sarif"
)

func TestRunHeadersFromStdin(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		settings *headersSettings
		input    string
		// expected are the substrings the output must carry.
		expected []string
		// unexpected are the ones it must not.
		unexpected []string
		// expectFindings says the run should ask for a failing status.
		expectFindings bool
		// expectError says the run should fail outright.
		expectError bool
	}{
		{
			name:     "a served header block is analysed",
			settings: &headersSettings{},
			input:    "Content-Type: text/html\nX-Content-Type-Options: sniff\n",
			expected: []string{"x_content_type_options_bad_value", "value: sniff"},
		},
		{
			name:       "--min-level withholds what is below it",
			settings:   &headersSettings{minLevel: string(sarif.LevelError)},
			input:      "Content-Type: text/html\nServer: nginx\n",
			unexpected: []string{"server_header_exposure"},
			expected:   []string{"missing_x_content_type_options"},
		},
		{
			name:     "a header block that is right of every rule reports nothing",
			settings: &headersSettings{minLevel: string(sarif.LevelWarning)},
			input: "Content-Type: text/html\n" +
				"X-Content-Type-Options: nosniff\n" +
				"Strict-Transport-Security: max-age=63072000; includeSubDomains; preload\n" +
				"Content-Security-Policy: default-src 'self'; base-uri 'self'; form-action 'self'; " +
				"frame-ancestors 'self'; require-sri-for script style\n" +
				"Cross-Origin-Opener-Policy: same-origin\n" +
				"Cross-Origin-Embedder-Policy: require-corp\n" +
				"Cross-Origin-Resource-Policy: same-origin\n" +
				"Permissions-Policy: camera=()\n",
			expected: []string{"No findings."},
		},
		{
			name:           "--exit-code asks for the status when something was reported",
			settings:       &headersSettings{minLevel: string(sarif.LevelError), exitCode: true},
			input:          "Content-Type: text/html\nServer: nginx\n",
			expected:       []string{"missing_x_content_type_options"},
			expectFindings: true,
		},
		{
			name: "--exit-code is quiet when nothing survived the filter",
			settings: &headersSettings{
				minLevel: string(sarif.LevelWarning),
				exitCode: true,
			},
			input: "Content-Type: text/html\n" +
				"X-Content-Type-Options: nosniff\n" +
				"Strict-Transport-Security: max-age=63072000; includeSubDomains; preload\n" +
				"Content-Security-Policy: default-src 'self'; base-uri 'self'; form-action 'self'; " +
				"frame-ancestors 'self'; require-sri-for script style\n" +
				"Cross-Origin-Opener-Policy: same-origin\n" +
				"Cross-Origin-Embedder-Policy: require-corp\n" +
				"Cross-Origin-Resource-Policy: same-origin\n" +
				"Permissions-Policy: camera=()\n",
			expected: []string{"No findings."},
		},
		{
			name:        "nothing on standard input is an error rather than a clean run",
			settings:    &headersSettings{},
			input:       "",
			expectError: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			var buffer bytes.Buffer

			err := runHeaders(context.Background(), testCase.settings, strings.NewReader(testCase.input), &buffer)

			switch {
			case testCase.expectError:
				if err == nil || errors.Is(err, errFindings) {
					t.Fatalf("runHeaders error = %v, want a failure", err)
				}

				return
			case testCase.expectFindings:
				if !errors.Is(err, errFindings) {
					t.Fatalf("runHeaders error = %v, want the findings sentinel", err)
				}
			case err != nil:
				t.Fatalf("runHeaders error = %v", err)
			}

			output := buffer.String()

			for _, expected := range testCase.expected {
				if !strings.Contains(output, expected) {
					t.Errorf("output does not carry %q:\n%s", expected, output)
				}
			}

			for _, unexpected := range testCase.unexpected {
				if strings.Contains(output, unexpected) {
					t.Errorf("output carries %q, which it should not:\n%s", unexpected, output)
				}
			}
		})
	}
}

func TestRunHeadersJson(t *testing.T) {
	t.Parallel()

	// The response carries a document, which is what makes the analysis hold it to the headers that
	// only protect one: a bodyless response has its Content-Security-Policy finding downgraded.
	server := httptest.NewServer(
		http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("Content-Type", "text/html")
			writer.Header().Set("X-Content-Type-Options", "nosniff")
			writer.Header().Set("Server", "nginx/1.24.0")
			writer.WriteHeader(http.StatusOK)

			// A failed write shows up as the request failing, which the subtest reports; the
			// handler runs on the server's goroutine and has no test to report to itself.
			_, _ = writer.Write([]byte("<!doctype html><title>t</title>"))
		}),
	)

	// Closing is deferred to the cleanup rather than to this function returning: the subtests are
	// parallel, so they run after the body they were declared in has already returned.
	t.Cleanup(server.Close)

	testCases := []struct {
		name     string
		minLevel string
		// expectedRules are the rule ids the log should hold, and the results with them.
		expectedRules []string
		// unexpectedRules must appear in neither the rule table nor the results.
		unexpectedRules []string
	}{
		{
			name:            "the log holds what was found, at the level asked for",
			minLevel:        string(sarif.LevelError),
			expectedRules:   []string{"missing_content_security_policy", "missing_strict_transport_security"},
			unexpectedRules: []string{"server_header_exposure", "missing_x_content_type_options"},
		},
		{
			name:          "a lower level lets more through",
			minLevel:      string(sarif.LevelNote),
			expectedRules: []string{"missing_content_security_policy", "server_header_exposure"},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			var buffer bytes.Buffer

			settings := &headersSettings{
				target:   server.URL,
				method:   http.MethodGet,
				minLevel: testCase.minLevel,
				asJson:   true,
			}

			if err := runHeaders(context.Background(), settings, strings.NewReader(""), &buffer); err != nil {
				t.Fatalf("runHeaders error = %v", err)
			}

			var log sarif.Log
			if err := json.Unmarshal(buffer.Bytes(), &log); err != nil {
				t.Fatalf("json unmarshal error = %v, over:\n%s", err, buffer.String())
			}

			if log.Version != sarif.Version {
				t.Errorf("version = %q, want %q", log.Version, sarif.Version)
			}

			if len(log.Runs) != 1 {
				t.Fatalf("runs = %d, want 1", len(log.Runs))
			}

			run := log.Runs[0]

			if url, _ := run.Properties["url"].(string); url != server.URL {
				t.Errorf("run url = %q, want %q", url, server.URL)
			}

			raised := map[string]bool{}
			for _, result := range run.Results {
				raised[result.RuleId] = true
			}

			described := map[string]bool{}
			if run.Tool != nil && run.Tool.Driver != nil {
				for _, rule := range run.Tool.Driver.Rules {
					described[rule.Id] = true
				}
			}

			for _, ruleId := range testCase.expectedRules {
				if !raised[ruleId] {
					t.Errorf("results do not hold %q", ruleId)
				}

				// A rule table describing rules that raised nothing is what filtering would leave
				// behind if it were not pruned with the results.
				if !described[ruleId] {
					t.Errorf("the rule table does not describe %q", ruleId)
				}
			}

			for _, ruleId := range testCase.unexpectedRules {
				if raised[ruleId] {
					t.Errorf("results hold %q, which the filter should have withheld", ruleId)
				}

				if described[ruleId] {
					t.Errorf("the rule table describes %q, which raised nothing", ruleId)
				}
			}
		})
	}
}
