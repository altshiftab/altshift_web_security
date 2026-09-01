package main

import (
	"testing"
)

func TestSplitTarget(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name         string
		target       string
		expectedHost string
		expectedPort int
		expectError  bool
	}{
		{name: "a bare host", target: "example.com", expectedHost: "example.com", expectedPort: 443},
		{name: "a host and a port", target: "example.com:8443", expectedHost: "example.com", expectedPort: 8443},
		{
			// A URL is a reasonable thing to paste out of a browser, and the
			// scheme and path are not part of a host.
			name:         "a url",
			target:       "https://example.com/a/path",
			expectedHost: "example.com",
			expectedPort: 443,
		},
		{
			name:         "a url with a port",
			target:       "https://example.com:8443/a/path",
			expectedHost: "example.com",
			expectedPort: 8443,
		},
		{name: "an ipv4 address", target: "192.0.2.1", expectedHost: "192.0.2.1", expectedPort: 443},
		{name: "an ipv4 address and a port", target: "192.0.2.1:8443", expectedHost: "192.0.2.1", expectedPort: 8443},
		{
			// A bare IPv6 address is full of colons, none of which introduces a
			// port.
			name:         "a bare ipv6 address",
			target:       "2001:db8::1",
			expectedHost: "2001:db8::1",
			expectedPort: 443,
		},
		{
			name:         "a bracketed ipv6 address and a port",
			target:       "[2001:db8::1]:8443",
			expectedHost: "2001:db8::1",
			expectedPort: 8443,
		},
		{
			name:         "a bracketed ipv6 address with no port",
			target:       "[2001:db8::1]",
			expectedHost: "2001:db8::1",
			expectedPort: 443,
		},
		{name: "surrounding space", target: "  example.com  ", expectedHost: "example.com", expectedPort: 443},
		{name: "nothing", target: "", expectError: true},
		{name: "only space", target: "   ", expectError: true},
		{name: "a port that is not a number", target: "example.com:https", expectError: true},
		{name: "a port outside the range", target: "example.com:70000", expectError: true},
		{name: "a port of zero", target: "example.com:0", expectError: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			host, port, err := splitTarget(testCase.target)

			if testCase.expectError {
				if err == nil {
					t.Fatalf("splitTarget(%q) = %q, %d, want an error", testCase.target, host, port)
				}

				return
			}

			if err != nil {
				t.Fatalf("splitTarget(%q) error = %v", testCase.target, err)
			}

			if host != testCase.expectedHost {
				t.Errorf("host = %q, want %q", host, testCase.expectedHost)
			}

			if port != testCase.expectedPort {
				t.Errorf("port = %d, want %d", port, testCase.expectedPort)
			}
		})
	}
}

// The subcommand's own declaration being wrong is a mistake in this program rather
// than in what a user typed, and Validate is what catches it before a parse that
// happens to reach it.
func TestSubcommandDeclarationsAreValid(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		subcommand *command
	}{
		{name: "headers", subcommand: newHeadersCommand()},
		{name: "tls", subcommand: newTlsCommand()},
		{name: "security-txt", subcommand: newSecurityTxtCommand()},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if err := testCase.subcommand.parser.Validate(); err != nil {
				t.Errorf("the %s parser's own declaration is wrong: %v", testCase.name, err)
			}
		})
	}
}
