package analysis

import (
	"strings"
	"testing"
	"time"

	"github.com/altshiftab/altshift_web_security/pkg/http/security_txt_analysis/retrieval"
	"github.com/altshiftab/altshift_web_security/pkg/http/security_txt_analysis/rule_id"
	"github.com/altshiftab/utils_go/pkg/http/types/security_txt"
	"github.com/altshiftab/utils_go/pkg/sarif"
)

// now is the moment every case is judged against, so that a test does not change its
// mind as the clock moves.
var now = time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC)

// retrievalOf builds what a retrieval of this file at the well-known path, served as
// RFC 9116 requires, would have found.
func retrievalOf(t *testing.T, body string) *retrieval.Retrieval {
	t.Helper()

	const url = "https://example.test/.well-known/security.txt"

	found := &retrieval.Retrieval{
		Host: "example.test",
		Now:  now,
		Found: &retrieval.Attempt{
			Url:         url,
			FinalUrl:    url,
			WellKnown:   true,
			StatusCode:  200,
			ContentType: "text/plain; charset=utf-8",
			Body:        []byte(body),
		},
	}
	found.Attempts = []*retrieval.Attempt{found.Found}

	parsed, err := security_txt.Parse([]byte(body))
	if err != nil {
		found.ParseError = err.Error()

		return found
	}

	found.Parsed = parsed

	return found
}

// cleanFile is a security.txt with nothing wrong with it.
const cleanFile = "Contact: mailto:security@example.test\n" +
	"Expires: 2026-12-01T00:00:00Z\n" +
	"Canonical: https://example.test/.well-known/security.txt\n"

func ruleIds(run *sarif.Run) []string {
	var ids []string
	for _, result := range run.Results {
		ids = append(ids, result.RuleId)
	}

	return ids
}

func holds(ids []string, wanted string) bool {
	for _, id := range ids {
		if id == wanted {
			return true
		}
	}

	return false
}

// A file with nothing wrong with it draws nothing at all.
func TestAnalyzeSaysNothingAboutACleanFile(t *testing.T) {
	t.Parallel()

	run, err := Analyze(retrievalOf(t, cleanFile))
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}

	if run == nil {
		t.Fatal("no run was produced")
	}

	for _, result := range run.Results {
		t.Errorf("a clean file was reported for %q: %s", result.RuleId, result.Message.Text)
	}
}

func TestAnalyzeContents(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		body string
		// expected are the rule ids the run must hold, unexpected the ones it must
		// not.
		expected   []string
		unexpected []string
	}{
		{
			name:     "no contact",
			body:     "Expires: 2026-12-01T00:00:00Z\n",
			expected: []string{rule_id.MissingContact},
		},
		{
			name:     "no expires",
			body:     "Contact: mailto:a@example.test\n",
			expected: []string{rule_id.MissingExpires},
		},
		{
			// The most common thing wrong with a real security.txt: it was written
			// once and never revisited.
			name:       "expired",
			body:       "Contact: mailto:a@example.test\nExpires: 2025-01-01T00:00:00Z\n",
			expected:   []string{rule_id.Expired},
			unexpected: []string{rule_id.MissingExpires, rule_id.ExpiresTooDistant},
		},
		{
			name:       "expires further out than the recommended year",
			body:       "Contact: mailto:a@example.test\nExpires: 2030-01-01T00:00:00Z\n",
			expected:   []string{rule_id.ExpiresTooDistant},
			unexpected: []string{rule_id.Expired},
		},
		{
			name:       "expires just inside the recommended year",
			body:       "Contact: mailto:a@example.test\nExpires: 2027-08-01T00:00:00Z\n",
			unexpected: []string{rule_id.ExpiresTooDistant, rule_id.Expired},
		},
		{
			name: "two expires fields",
			body: "Contact: mailto:a@example.test\nExpires: 2026-12-01T00:00:00Z\n" +
				"Expires: 2026-11-01T00:00:00Z\n",
			expected: []string{rule_id.MultipleExpires},
		},
		{
			name: "two preferred-languages fields",
			body: "Contact: mailto:a@example.test\nExpires: 2026-12-01T00:00:00Z\n" +
				"Preferred-Languages: en\nPreferred-Languages: sv\n",
			expected: []string{rule_id.MultiplePreferredLanguages},
		},
		{
			name:     "a contact that is not a uri",
			body:     "Contact: security@example.test\nExpires: 2026-12-01T00:00:00Z\n",
			expected: []string{rule_id.MalformedField, rule_id.MissingContact},
		},
		{
			// Section 2.5.2: the contents should not then be trusted.
			name: "a canonical that does not name where the file was found",
			body: "Contact: mailto:a@example.test\nExpires: 2026-12-01T00:00:00Z\n" +
				"Canonical: https://elsewhere.test/.well-known/security.txt\n",
			expected: []string{rule_id.CanonicalMismatch},
		},
		{
			name:       "no canonical at all",
			body:       "Contact: mailto:a@example.test\nExpires: 2026-12-01T00:00:00Z\n",
			unexpected: []string{rule_id.CanonicalMismatch},
		},
		{
			name: "one canonical of several matches",
			body: "Contact: mailto:a@example.test\nExpires: 2026-12-01T00:00:00Z\n" +
				"Canonical: https://elsewhere.test/.well-known/security.txt\n" +
				"Canonical: https://example.test/.well-known/security.txt\n",
			unexpected: []string{rule_id.CanonicalMismatch},
		},
		{
			name:       "a file that is not a security.txt",
			body:       "this is not a security.txt\n",
			expected:   []string{rule_id.SyntaxError},
			unexpected: []string{rule_id.MissingContact},
		},
		{
			name:     "an empty file",
			body:     "",
			expected: []string{rule_id.MissingContact, rule_id.MissingExpires},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			run, err := Analyze(retrievalOf(t, testCase.body))
			if err != nil {
				t.Fatalf("analyze: %v", err)
			}

			ids := ruleIds(run)

			for _, wanted := range testCase.expected {
				if !holds(ids, wanted) {
					t.Errorf("%q was not reported; the run holds %v", wanted, ids)
				}
			}

			for _, unwanted := range testCase.unexpected {
				if holds(ids, unwanted) {
					t.Errorf("%q was reported, and should not have been", unwanted)
				}
			}
		})
	}
}

// RFC 9116 has as much to say about how the file is served as about what it says.
func TestAnalyzeService(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		// mutate turns a clean retrieval into the one under test.
		mutate     func(*retrieval.Retrieval)
		expected   []string
		unexpected []string
	}{
		{
			name: "nothing served at either path",
			mutate: func(found *retrieval.Retrieval) {
				found.Found = nil
				found.Parsed = nil
				found.Attempts = []*retrieval.Attempt{
					{Url: "https://example.test/.well-known/security.txt", WellKnown: true, StatusCode: 404},
					{Url: "https://example.test/security.txt", StatusCode: 404},
				}
			},
			expected: []string{rule_id.Missing},
			// With no file there is nothing to say about its contents, and saying
			// it for each check would bury the one finding that matters.
			unexpected: []string{rule_id.MissingContact, rule_id.MissingExpires, rule_id.BadContentType},
		},
		{
			name: "found only at the legacy path",
			mutate: func(found *retrieval.Retrieval) {
				found.Found.WellKnown = false
				found.Found.Url = "https://example.test/security.txt"
				found.Found.FinalUrl = found.Found.Url
			},
			expected: []string{rule_id.NotAtWellKnownPath},
		},
		{
			name: "redirected off https",
			mutate: func(found *retrieval.Retrieval) {
				found.Found.FinalUrl = "http://example.test/.well-known/security.txt"
			},
			expected: []string{rule_id.NotHttps},
		},
		{
			name: "served as html",
			mutate: func(found *retrieval.Retrieval) {
				found.Found.ContentType = "text/html; charset=utf-8"
			},
			expected: []string{rule_id.BadContentType},
		},
		{
			name: "served without a charset",
			mutate: func(found *retrieval.Retrieval) {
				found.Found.ContentType = "text/plain"
			},
			expected: []string{rule_id.BadContentType},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			found := retrievalOf(t, cleanFile)
			testCase.mutate(found)

			run, err := Analyze(found)
			if err != nil {
				t.Fatalf("analyze: %v", err)
			}

			ids := ruleIds(run)

			for _, wanted := range testCase.expected {
				if !holds(ids, wanted) {
					t.Errorf("%q was not reported; the run holds %v", wanted, ids)
				}
			}

			for _, unwanted := range testCase.unexpected {
				if holds(ids, unwanted) {
					t.Errorf("%q was reported, and should not have been", unwanted)
				}
			}
		})
	}
}

// Every result has to carry a level SARIF defines, a message, and a rule the run's own
// table describes.
func TestEmittedResultsAreValidSarif(t *testing.T) {
	t.Parallel()

	validLevels := map[sarif.Level]bool{
		sarif.LevelNone:    true,
		sarif.LevelNote:    true,
		sarif.LevelWarning: true,
		sarif.LevelError:   true,
	}

	bodies := map[string]string{
		"clean":                cleanFile,
		"everything wrong":     "Contact: not-a-uri\nExpires: 2025-01-01T00:00:00Z\nExpires: 2024-01-01T00:00:00Z\nCanonical: https://elsewhere.test/x\n",
		"not a security.txt":   "this is not a security.txt\n",
		"nothing in it at all": "",
	}

	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			run, err := Analyze(retrievalOf(t, body))
			if err != nil {
				t.Fatalf("analyze: %v", err)
			}

			if run == nil || run.Tool == nil || run.Tool.Driver == nil {
				t.Fatal("no run was produced")
			}

			described := map[string]bool{}
			for _, rule := range run.Tool.Driver.Rules {
				described[rule.Id] = true
			}

			for _, result := range run.Results {
				if !validLevels[result.Level] {
					t.Errorf("rule %q emitted level %q, which SARIF does not define", result.RuleId, result.Level)
				}

				if result.Kind != sarif.KindFail && result.Level != sarif.LevelNone {
					t.Errorf(
						"rule %q has kind %q with level %q; SARIF requires level none for any kind but fail",
						result.RuleId,
						result.Kind,
						result.Level,
					)
				}

				if result.Message == nil || strings.TrimSpace(result.Message.Text) == "" {
					t.Errorf("rule %q emitted no message", result.RuleId)
				}

				if _, found := result.Properties["subject"]; !found {
					t.Errorf("rule %q carries no subject, so a report has nothing to head it with", result.RuleId)
				}

				if !described[result.RuleId] {
					t.Errorf("rule %q was raised but is not in the rule table", result.RuleId)
				}
			}
		})
	}
}

func TestAnalyzeTakesNothing(t *testing.T) {
	t.Parallel()

	run, err := Analyze(nil)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}

	if run != nil {
		t.Error("a run was produced from no retrieval at all")
	}
}
