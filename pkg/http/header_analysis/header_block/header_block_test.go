package header_block

import (
	"errors"
	"net/http"
	"reflect"
	"testing"

	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
)

func TestParse(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		input    string
		expected http.Header
		// expectedErr is the sentinel a failure wraps, nil where the block is read.
		expectedErr error
	}{
		{
			name:     "fields alone, ending without a blank line",
			input:    "Server: nginx\nX-Content-Type-Options: nosniff",
			expected: http.Header{"Server": {"nginx"}, "X-Content-Type-Options": {"nosniff"}},
		},
		{
			name:     "a whole response, status line and all",
			input:    "HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n",
			expected: http.Header{"Server": {"nginx"}},
		},
		{
			name:     "HTTP/2 status line",
			input:    "HTTP/2 204 No Content\nServer: nginx\n",
			expected: http.Header{"Server": {"nginx"}},
		},
		{
			name:     "crlf endings",
			input:    "Server: nginx\r\nVary: Accept\r\n",
			expected: http.Header{"Server": {"nginx"}, "Vary": {"Accept"}},
		},
		{
			name:     "lf endings",
			input:    "Server: nginx\nVary: Accept\n",
			expected: http.Header{"Server": {"nginx"}, "Vary": {"Accept"}},
		},
		{
			name:     "leading blank lines",
			input:    "\n\r\n\nServer: nginx\n",
			expected: http.Header{"Server": {"nginx"}},
		},
		{
			name:  "a repeated field keeps both values, which is what the analysis reports on",
			input: "Content-Security-Policy: default-src 'self'\nContent-Security-Policy: script-src 'none'\n",
			expected: http.Header{
				"Content-Security-Policy": {"default-src 'self'", "script-src 'none'"},
			},
		},
		{
			name:     "a folded field is joined into one value",
			input:    "Content-Security-Policy: default-src 'self';\r\n  script-src 'none'\r\nServer: nginx\r\n",
			expected: http.Header{"Content-Security-Policy": {"default-src 'self'; script-src 'none'"}, "Server": {"nginx"}},
		},
		{
			name:     "the name is canonicalised, so a lowercase paste is found by the analysis",
			input:    "strict-transport-security: max-age=31536000\n",
			expected: http.Header{"Strict-Transport-Security": {"max-age=31536000"}},
		},
		{
			name:     "a field with no value",
			input:    "X-Empty:\n",
			expected: http.Header{"X-Empty": {""}},
		},
		{
			name:     "a body after the blank line is not read",
			input:    "HTTP/1.1 200 OK\nContent-Type: text/html\n\n<!doctype html>\nnot: a field\n",
			expected: http.Header{"Content-Type": {"text/html"}},
		},
		{
			name: "of a redirect followed, the response finally served is read",
			input: "HTTP/1.1 301 Moved Permanently\r\nLocation: https://example.com/\r\nServer: old\r\n\r\n" +
				"HTTP/2 200\r\ncontent-type: text/html\r\nserver: new\r\n\r\n",
			expected: http.Header{"Content-Type": {"text/html"}, "Server": {"new"}},
		},
		{
			name:     "an interim 100 Continue is passed over",
			input:    "HTTP/1.1 100 Continue\n\nHTTP/1.1 200 OK\nServer: nginx\n\nbody",
			expected: http.Header{"Server": {"nginx"}},
		},
		{
			name:     "HTTP/2 pseudo-header fields are skipped",
			input:    ":status: 200\ncontent-type: text/html\n",
			expected: http.Header{"Content-Type": {"text/html"}},
		},
		{name: "empty", input: "", expectedErr: altshiftErrors.ErrValidationError},
		{name: "whitespace only", input: "\n \n", expectedErr: altshiftErrors.ErrValidationError},
		{name: "a status line and nothing else", input: "HTTP/1.1 200 OK\n", expectedErr: altshiftErrors.ErrValidationError},
		{name: "pseudo-header fields alone", input: ":status: 200\n", expectedErr: altshiftErrors.ErrValidationError},
		{name: "not a header field", input: "this is not a header\n", expectedErr: altshiftErrors.ErrParseError},
		{name: "a name with a space in it", input: "Not A Name: value\n", expectedErr: altshiftErrors.ErrParseError},
		{name: "a space before the colon", input: "Server : nginx\n", expectedErr: altshiftErrors.ErrParseError},
		{name: "a field after garbage", input: "Server: nginx\ngarbage\n", expectedErr: altshiftErrors.ErrParseError},
		{name: "indented first line", input: " Server: nginx\n", expectedErr: altshiftErrors.ErrParseError},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			header, err := Parse(testCase.input)

			if testCase.expectedErr != nil {
				if err == nil {
					t.Fatalf("Parse(%q) = %v, want an error", testCase.input, header)
				}

				// Either is a mistake in what was pasted, and an endpoint answers it with a 4xx.
				if !errors.Is(err, testCase.expectedErr) {
					t.Errorf("Parse(%q) error = %v, want it to wrap %v", testCase.input, err, testCase.expectedErr)
				}

				if errors.Is(testCase.expectedErr, altshiftErrors.ErrValidationError) {
					if _, ok := errors.AsType[*empty_error.Error](err); !ok {
						t.Errorf("Parse(%q) error = %v, want an empty error", testCase.input, err)
					}
				}

				return
			}

			if err != nil {
				t.Fatalf("Parse(%q) error = %v", testCase.input, err)
			}

			if !reflect.DeepEqual(header, testCase.expected) {
				t.Errorf("Parse(%q) = %v, want %v", testCase.input, header, testCase.expected)
			}
		})
	}
}
