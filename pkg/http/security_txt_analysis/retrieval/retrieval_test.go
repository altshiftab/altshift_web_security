package retrieval

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newHost serves the given paths and nothing else, and returns a client whose
// requests all land on it. The retrieval builds https URLs from a host name, so
// redirecting the transport is what lets a test stand in for one without a
// certificate.
func newHost(t *testing.T, bodies map[string]string) *http.Client {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, found := bodies[request.URL.Path]
		if !found {
			writer.WriteHeader(http.StatusNotFound)

			return
		}

		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")

		if _, err := writer.Write([]byte(body)); err != nil {
			t.Errorf("write: %v", err)
		}
	}))

	t.Cleanup(server.Close)

	return &http.Client{Transport: &redirectingTransport{target: server.URL}}
}

// errNoResponse stands for a round trip that returned neither a response nor an
// error, which the transport contract forbids and the type system permits.
var errNoResponse = errors.New("the round trip returned no response")

// redirectingTransport sends every request to one server, whatever host and scheme it
// names.
type redirectingTransport struct {
	target string
}

func (transport *redirectingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	rewritten := request.Clone(request.Context())

	target := strings.TrimPrefix(transport.target, "http://")
	rewritten.URL.Scheme = "http"
	rewritten.URL.Host = target
	rewritten.Host = target

	response, err := http.DefaultTransport.RoundTrip(rewritten)
	if err != nil {
		return nil, err
	}

	if response == nil {
		return nil, errNoResponse
	}

	// The caller reads FinalUrl off the response's request, and the scheme check
	// depends on it. Put back the https the retrieval asked for, so that a test
	// serving over plain http locally is not read as a host serving over http.
	if response.Request != nil && response.Request.URL != nil {
		response.Request.URL.Scheme = "https"
		response.Request.URL.Host = request.URL.Host
	}

	return response, nil
}

func TestRetrieve(t *testing.T) {
	t.Parallel()

	const file = "Contact: mailto:a@example.com\nExpires: 2030-01-01T00:00:00Z\n"

	testCases := []struct {
		name   string
		bodies map[string]string
		// expectFound says a file should have been found, and expectWellKnown that
		// it was the one at the path RFC 9116 requires.
		expectFound     bool
		expectWellKnown bool
		// expectedAttempts is how many URLs should have been tried.
		expectedAttempts int
	}{
		{
			name:             "a file at the well-known path",
			bodies:           map[string]string{WellKnownPath: file},
			expectFound:      true,
			expectWellKnown:  true,
			expectedAttempts: 1,
		},
		{
			// The legacy path is only tried when the well-known one has nothing,
			// and a file found there is in the wrong place.
			name:             "a file only at the legacy path",
			bodies:           map[string]string{LegacyPath: file},
			expectFound:      true,
			expectWellKnown:  false,
			expectedAttempts: 2,
		},
		{
			// Section 3 requires the well-known one to be used when both exist.
			name:             "a file at both paths",
			bodies:           map[string]string{WellKnownPath: file, LegacyPath: "Contact: mailto:legacy@example.com\n"},
			expectFound:      true,
			expectWellKnown:  true,
			expectedAttempts: 1,
		},
		{
			name:             "no file at all",
			bodies:           map[string]string{},
			expectFound:      false,
			expectedAttempts: 2,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			found, err := Retrieve(
				context.Background(),
				"example.test",
				&Settings{Client: newHost(t, testCase.bodies)},
			)
			if err != nil {
				t.Fatalf("retrieve: %v", err)
			}

			if len(found.Attempts) != testCase.expectedAttempts {
				t.Errorf("attempts = %d, want %d", len(found.Attempts), testCase.expectedAttempts)
			}

			if (found.Found != nil) != testCase.expectFound {
				t.Fatalf("found = %v, want %v", found.Found != nil, testCase.expectFound)
			}

			if !testCase.expectFound {
				return
			}

			if found.Found.WellKnown != testCase.expectWellKnown {
				t.Errorf("well known = %v, want %v", found.Found.WellKnown, testCase.expectWellKnown)
			}

			if found.Parsed == nil {
				t.Fatalf("the file was found but not parsed: %s", found.ParseError)
			}

			if len(found.Parsed.SecurityTxt.Contacts) == 0 {
				t.Error("the parsed file names no contact")
			}

			if found.Now.IsZero() {
				t.Error("the retrieval recorded no time, so an Expires has nothing to be held against")
			}
		})
	}
}

func TestRetrieveRejectsNoHost(t *testing.T) {
	t.Parallel()

	if _, err := Retrieve(context.Background(), "", nil); err == nil {
		t.Error("a retrieval with no host was accepted")
	}
}

// A file that is served but is not a security.txt is found and not parsed, which is
// a different finding from one that is not served at all.
func TestRetrieveKeepsAnUnparsableFile(t *testing.T) {
	t.Parallel()

	found, err := Retrieve(
		context.Background(),
		"example.test",
		&Settings{Client: newHost(t, map[string]string{WellKnownPath: "this is not a security.txt\n"})},
	)
	if err != nil {
		t.Fatalf("retrieve: %v", err)
	}

	if found.Found == nil {
		t.Fatal("the file was not found")
	}

	if found.Parsed != nil {
		t.Error("a file that is not a security.txt was parsed as one")
	}

	if found.ParseError == "" {
		t.Error("nothing said why the file could not be parsed")
	}
}

func TestContentTypeIsPlainUtf8(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		contentType string
		expected    bool
	}{
		{name: "as required", contentType: "text/plain; charset=utf-8", expected: true},
		{name: "in a different case", contentType: "Text/Plain; CharSet=UTF-8", expected: true},
		{name: "with the charset quoted", contentType: "text/plain; charset=\"utf-8\"", expected: true},
		{name: "with other parameters first", contentType: "text/plain; foo=bar; charset=utf-8", expected: true},
		{name: "no charset", contentType: "text/plain", expected: false},
		{name: "a different charset", contentType: "text/plain; charset=iso-8859-1", expected: false},
		{name: "a different type", contentType: "text/html; charset=utf-8", expected: false},
		{name: "none at all", contentType: "", expected: false},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			found := &Retrieval{Found: &Attempt{ContentType: testCase.contentType}}

			if got := found.ContentTypeIsPlainUtf8(); got != testCase.expected {
				t.Errorf("ContentTypeIsPlainUtf8(%q) = %v, want %v", testCase.contentType, got, testCase.expected)
			}
		})
	}
}

func TestServedOverHttps(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		found    *Retrieval
		expected bool
	}{
		{
			name:     "https",
			found:    &Retrieval{Found: &Attempt{FinalUrl: "https://example.test/.well-known/security.txt"}},
			expected: true,
		},
		{
			// The request is always made over https, so this is a redirect that
			// took it off.
			name:     "redirected to http",
			found:    &Retrieval{Found: &Attempt{FinalUrl: "http://example.test/.well-known/security.txt"}},
			expected: false,
		},
		{name: "nothing was found", found: &Retrieval{}, expected: false},
		{name: "nothing at all", found: nil, expected: false},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := testCase.found.ServedOverHttps(); got != testCase.expected {
				t.Errorf("ServedOverHttps = %v, want %v", got, testCase.expected)
			}
		})
	}
}
