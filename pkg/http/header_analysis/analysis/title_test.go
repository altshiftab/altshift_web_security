package analysis

import (
	"net/http"
	"strings"
	"testing"

	"github.com/altshiftab/utils_go/pkg/sarif"
)

func TestTitle(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		header   http.Header
		ruleId   string
		expected string
	}{
		{
			name:     "an exposing header is named",
			header:   http.Header{"Server": {"nginx/1.25"}},
			ruleId:   "server_header_exposure",
			expected: "The Server header exposes system information",
		},
		{
			name:     "another exposing header",
			header:   http.Header{"X-Powered-By": {"PHP/8.2"}},
			ruleId:   "x_powered_by_header_exposure",
			expected: "The X-Powered-By header exposes system information",
		},
		{
			name:     "a deprecated header",
			header:   http.Header{"Public-Key-Pins": {"pin-sha256=\"x\"; max-age=10"}},
			ruleId:   "public_key_pins_deprecated",
			expected: "The Public-Key-Pins header is deprecated",
		},
		{
			// A rule whose title is a placeholder is called by what its message says was found.
			name:     "a rule whose wording depends on what was found",
			header:   http.Header{"Content-Security-Policy": {"script-src http://cdn.example.com"}},
			ruleId:   "",
			expected: "The http://cdn.example.com source of the script-src directive uses an http scheme",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			run, err := AnalyzeHeaders(testCase.header)
			if err != nil {
				t.Fatalf("analyze headers: %v", err)
			}
			if run == nil {
				t.Fatal("nil run")
			}

			var titles []string
			for _, result := range run.Results {
				if testCase.ruleId != "" && result.RuleId != testCase.ruleId {
					continue
				}
				titles = append(titles, Title(result))
			}

			found := false
			for _, title := range titles {
				if title == testCase.expected {
					found = true
				}
			}
			if !found {
				t.Errorf("expected %q among %q", testCase.expected, titles)
			}
		})
	}
}

// TestTitleIsNeverTheExplanation holds what the function is for, over everything a busy set of
// headers produces: no title is a placeholder, and none runs into a second sentence.
func TestTitleIsNeverTheExplanation(t *testing.T) {
	t.Parallel()

	run, err := AnalyzeHeaders(http.Header{
		"Server":                  {"nginx"},
		"X-Powered-By":            {"Express"},
		"X-Xss-Protection":        {"1; mode=block"},
		"Expect-Ct":               {"max-age=0"},
		"Content-Security-Policy": {"default-src *; script-src 'unsafe-inline' 'unsafe-eval' http://a.example data:"},
		"X-Frame-Options":         {"ALLOW-FROM x", "DENY"},
	})
	if err != nil {
		t.Fatalf("analyze headers: %v", err)
	}
	if run == nil || len(run.Results) == 0 {
		t.Fatal("expected results to title")
	}

	for _, result := range run.Results {
		title := Title(result)
		if title == "" || title == "DYNAMIC" || strings.Contains(title, ". ") {
			t.Errorf("rule %s: title %q", result.RuleId, title)
		}
	}
}

func TestTitleOfNothing(t *testing.T) {
	t.Parallel()

	if got := Title(nil); got != "" {
		t.Errorf("got %q", got)
	}
	if got := Title(&sarif.Result{RuleId: "some_rule"}); got != "some_rule" {
		t.Errorf("got %q, expected the rule id for a result with nothing else", got)
	}
}
