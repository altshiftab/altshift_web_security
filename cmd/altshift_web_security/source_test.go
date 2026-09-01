package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
)

func TestNormalizeUrl(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		target   string
		expected string
	}{
		{name: "empty", target: "", expected: ""},
		{name: "bare host", target: "example.com", expected: "https://example.com"},
		{name: "bare host with path", target: "example.com/a/b", expected: "https://example.com/a/b"},
		{name: "https kept", target: "https://example.com", expected: "https://example.com"},
		{
			name:     "http kept, as the caller asked to see what is served over it",
			target:   "http://example.com",
			expected: "http://example.com",
		},
		{name: "port alone is not a scheme", target: "example.com:8443", expected: "https://example.com:8443"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := normalizeUrl(testCase.target); got != testCase.expected {
				t.Errorf("normalizeUrl(%q) = %q, want %q", testCase.target, got, testCase.expected)
			}
		})
	}
}

func TestParseRequestHeaders(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		values      []string
		expected    http.Header
		expectError bool
	}{
		{name: "none", values: nil, expected: nil},
		{
			name:     "one",
			values:   []string{"User-Agent: probe/1"},
			expected: http.Header{"User-Agent": []string{"probe/1"}},
		},
		{
			name:     "no space after the colon",
			values:   []string{"User-Agent:probe/1"},
			expected: http.Header{"User-Agent": []string{"probe/1"}},
		},
		{
			name:     "the value keeps its own colons",
			values:   []string{"Referer: https://example.com:8443/a"},
			expected: http.Header{"Referer": []string{"https://example.com:8443/a"}},
		},
		{
			name:     "a repeated name is sent twice rather than replaced",
			values:   []string{"Accept: text/html", "Accept: text/plain"},
			expected: http.Header{"Accept": []string{"text/html", "text/plain"}},
		},
		{
			name:     "an empty value is still a field",
			values:   []string{"Accept-Encoding:"},
			expected: http.Header{"Accept-Encoding": []string{""}},
		},
		{name: "no colon", values: []string{"User-Agent probe/1"}, expectError: true},
		{name: "empty name", values: []string{": probe/1"}, expectError: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			header, err := parseRequestHeaders(testCase.values)

			if testCase.expectError {
				if err == nil {
					t.Fatalf("parseRequestHeaders(%q) = no error, want one", testCase.values)
				}

				// A malformed -H is a mistake in what was typed, and says so.
				if !errors.Is(err, altshiftErrors.ErrParseError) {
					t.Errorf("parseRequestHeaders(%q) error = %v, want a parse error", testCase.values, err)
				}

				return
			}

			if err != nil {
				t.Fatalf("parseRequestHeaders(%q) error = %v", testCase.values, err)
			}

			if !reflect.DeepEqual(header, testCase.expected) {
				t.Errorf("parseRequestHeaders(%q) = %v, want %v", testCase.values, header, testCase.expected)
			}
		})
	}
}

func TestParseHeaderBlock(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		input       string
		expected    http.Header
		expectError bool
	}{
		{
			name:     "fields alone, ending without a blank line",
			input:    "Server: nginx\nX-Content-Type-Options: nosniff",
			expected: http.Header{"Server": []string{"nginx"}, "X-Content-Type-Options": []string{"nosniff"}},
		},
		{
			name:     "a whole response, status line and all",
			input:    "HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n",
			expected: http.Header{"Server": []string{"nginx"}},
		},
		{
			name:     "HTTP/2 status line",
			input:    "HTTP/2 204 No Content\nServer: nginx\n",
			expected: http.Header{"Server": []string{"nginx"}},
		},
		{
			name:     "crlf endings",
			input:    "Server: nginx\r\nVary: Accept\r\n",
			expected: http.Header{"Server": []string{"nginx"}, "Vary": []string{"Accept"}},
		},
		{
			name:     "leading blank lines",
			input:    "\n\nServer: nginx\n",
			expected: http.Header{"Server": []string{"nginx"}},
		},
		{
			name:  "a repeated field keeps both values, which is what the analysis reports on",
			input: "Content-Security-Policy: default-src 'self'\nContent-Security-Policy: script-src 'none'\n",
			expected: http.Header{
				"Content-Security-Policy": []string{"default-src 'self'", "script-src 'none'"},
			},
		},
		{
			name:     "the name is canonicalised, so a lowercase paste is found by the analysis",
			input:    "strict-transport-security: max-age=31536000\n",
			expected: http.Header{"Strict-Transport-Security": []string{"max-age=31536000"}},
		},
		{
			name:     "a field with no value",
			input:    "X-Empty:\n",
			expected: http.Header{"X-Empty": []string{""}},
		},
		{name: "empty", input: "", expectError: true},
		{name: "whitespace only", input: "\n \n", expectError: true},
		{name: "a status line and nothing else", input: "HTTP/1.1 200 OK\n", expectError: true},
		{name: "not a header field", input: "this is not a header\n", expectError: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			header, err := parseHeaderBlock([]byte(testCase.input))

			if testCase.expectError {
				if err == nil {
					t.Fatalf("parseHeaderBlock(%q) = %v, want an error", testCase.input, header)
				}

				return
			}

			if err != nil {
				t.Fatalf("parseHeaderBlock(%q) error = %v", testCase.input, err)
			}

			if !reflect.DeepEqual(header, testCase.expected) {
				t.Errorf("parseHeaderBlock(%q) = %v, want %v", testCase.input, header, testCase.expected)
			}
		})
	}
}

func TestFetch(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		// settings is the run this case stands for, with the target filled in by the test.
		settings *headersSettings
		// requestHeaders is what -H would have parsed to.
		requestHeaders http.Header
		// expectedHeader is the header the analysis should be handed, by name and value.
		expectedName  string
		expectedValue string
		// expectedMethod and expectedRequest are what the server should have seen.
		expectedMethod  string
		expectedRequest map[string]string
	}{
		{
			name:            "the response headers reach the caller",
			settings:        &headersSettings{method: http.MethodGet},
			expectedName:    "X-Probe",
			expectedValue:   "final",
			expectedMethod:  http.MethodGet,
			expectedRequest: map[string]string{},
		},
		{
			name:            "the method is the one asked for",
			settings:        &headersSettings{method: http.MethodHead},
			expectedName:    "X-Probe",
			expectedValue:   "final",
			expectedMethod:  http.MethodHead,
			expectedRequest: map[string]string{},
		},
		{
			name:            "request headers are sent",
			settings:        &headersSettings{method: http.MethodGet},
			requestHeaders:  http.Header{"X-Sent": []string{"yes"}},
			expectedName:    "X-Probe",
			expectedValue:   "final",
			expectedMethod:  http.MethodGet,
			expectedRequest: map[string]string{"X-Sent": "yes"},
		},
		{
			// Left to itself the transport asks for gzip and then strips Content-Encoding and
			// Content-Length off what it returns, which is two of the three fields that decide
			// whether a response counts as carrying a document.
			name:            "nothing asks for gzip on the caller's behalf",
			settings:        &headersSettings{method: http.MethodGet},
			expectedName:    "X-Probe",
			expectedValue:   "final",
			expectedMethod:  http.MethodGet,
			expectedRequest: map[string]string{"Accept-Encoding": ""},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			var seenMethod string
			var seenHeader http.Header

			server := httptest.NewServer(
				http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
					seenMethod = request.Method
					seenHeader = request.Header.Clone()

					writer.Header().Set("X-Probe", "final")
					writer.WriteHeader(http.StatusOK)
				}),
			)
			defer server.Close()

			header, err := fetch(context.Background(), server.URL, testCase.settings, testCase.requestHeaders)
			if err != nil {
				t.Fatalf("fetch error = %v", err)
			}

			if got := header.Get(testCase.expectedName); got != testCase.expectedValue {
				t.Errorf("response %s = %q, want %q", testCase.expectedName, got, testCase.expectedValue)
			}

			if seenMethod != testCase.expectedMethod {
				t.Errorf("request method = %q, want %q", seenMethod, testCase.expectedMethod)
			}

			for name, expected := range testCase.expectedRequest {
				if got := seenHeader.Get(name); got != expected {
					t.Errorf("request %s = %q, want %q", name, got, expected)
				}
			}
		})
	}
}

func TestFetchRedirects(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		// noFollow is what --no-follow sets.
		noFollow bool
		// expectedProbe says which response was analysed: the redirect, or what it pointed at.
		expectedProbe string
	}{
		{
			name:          "the document behind a redirect is what gets analysed",
			noFollow:      false,
			expectedProbe: "final",
		},
		{
			name:          "--no-follow analyses the redirect itself",
			noFollow:      true,
			expectedProbe: "redirect",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			mux := http.NewServeMux()
			mux.HandleFunc("/final", func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("X-Probe", "final")
				writer.WriteHeader(http.StatusOK)
			})
			mux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
				writer.Header().Set("X-Probe", "redirect")
				http.Redirect(writer, request, "/final", http.StatusFound)
			})

			server := httptest.NewServer(mux)
			defer server.Close()

			settings := &headersSettings{method: http.MethodGet, noFollow: testCase.noFollow}

			header, err := fetch(context.Background(), server.URL, settings, nil)
			if err != nil {
				t.Fatalf("fetch error = %v", err)
			}

			if got := header.Get("X-Probe"); got != testCase.expectedProbe {
				t.Errorf("analysed response X-Probe = %q, want %q", got, testCase.expectedProbe)
			}
		})
	}
}
