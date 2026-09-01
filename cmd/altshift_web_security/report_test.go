package main

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/altshiftab/utils_go/pkg/sarif"
)

// makeResult is the shape the analysis returns, in as few words as a test needs.
func makeResult(ruleId string, level sarif.Level, message string, properties sarif.PropertyBag) *sarif.Result {
	return &sarif.Result{
		RuleId:     ruleId,
		Level:      level,
		Message:    &sarif.Message{Text: message},
		Properties: properties,
	}
}

func TestParseLevel(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		value    string
		expected sarif.Level
	}{
		{name: "error", value: "error", expected: sarif.LevelError},
		{name: "warning", value: "warning", expected: sarif.LevelWarning},
		{name: "note", value: "note", expected: sarif.LevelNote},
		{name: "none", value: "none", expected: sarif.LevelNone},
		{name: "unset withholds nothing", value: "", expected: sarif.LevelNone},
		{name: "unknown withholds nothing", value: "critical", expected: sarif.LevelNone},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := parseLevel(testCase.value); got != testCase.expected {
				t.Errorf("parseLevel(%q) = %q, want %q", testCase.value, got, testCase.expected)
			}
		})
	}
}

func TestFilterResults(t *testing.T) {
	t.Parallel()

	results := []*sarif.Result{
		makeResult("a", sarif.LevelNone, "a", nil),
		makeResult("b", sarif.LevelNote, "b", nil),
		makeResult("c", sarif.LevelWarning, "c", nil),
		makeResult("d", sarif.LevelError, "d", nil),
	}

	testCases := []struct {
		name     string
		results  []*sarif.Result
		minLevel sarif.Level
		expected []string
	}{
		{name: "none keeps everything", results: results, minLevel: sarif.LevelNone, expected: []string{"a", "b", "c", "d"}},
		{name: "note", results: results, minLevel: sarif.LevelNote, expected: []string{"b", "c", "d"}},
		{name: "warning", results: results, minLevel: sarif.LevelWarning, expected: []string{"c", "d"}},
		{name: "error", results: results, minLevel: sarif.LevelError, expected: []string{"d"}},
		{name: "nothing to filter", results: nil, minLevel: sarif.LevelNone, expected: nil},
		{
			name:     "a nil result is dropped rather than carried into the report",
			results:  []*sarif.Result{nil, makeResult("d", sarif.LevelError, "d", nil)},
			minLevel: sarif.LevelNone,
			expected: []string{"d"},
		},
		{
			name:     "a level the ranking does not know is treated as the least",
			results:  []*sarif.Result{makeResult("x", sarif.Level("DYNAMIC"), "x", nil)},
			minLevel: sarif.LevelNote,
			expected: nil,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			var got []string
			for _, result := range filterResults(testCase.results, testCase.minLevel) {
				got = append(got, result.RuleId)
			}

			if !reflect.DeepEqual(got, testCase.expected) {
				t.Errorf("filterResults(..., %q) = %v, want %v", testCase.minLevel, got, testCase.expected)
			}
		})
	}
}

func TestSortResults(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		results  []*sarif.Result
		expected []string
	}{
		{
			name: "the worst comes first",
			results: []*sarif.Result{
				makeResult("note", sarif.LevelNote, "", nil),
				makeResult("error", sarif.LevelError, "", nil),
				makeResult("none", sarif.LevelNone, "", nil),
				makeResult("warning", sarif.LevelWarning, "", nil),
			},
			expected: []string{"error", "warning", "note", "none"},
		},
		{
			name: "within a level the order the analysis produced is kept",
			results: []*sarif.Result{
				makeResult("first", sarif.LevelError, "", nil),
				makeResult("second", sarif.LevelError, "", nil),
				makeResult("third", sarif.LevelError, "", nil),
			},
			expected: []string{"first", "second", "third"},
		},
		{name: "nothing to sort", results: nil, expected: nil},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			sortResults(testCase.results)

			var got []string
			for _, result := range testCase.results {
				got = append(got, result.RuleId)
			}

			if !reflect.DeepEqual(got, testCase.expected) {
				t.Errorf("sortResults = %v, want %v", got, testCase.expected)
			}
		})
	}
}

func TestPruneRules(t *testing.T) {
	t.Parallel()

	rules := []*sarif.ReportingDescriptor{{Id: "a"}, {Id: "b"}, {Id: "c"}}

	testCases := []struct {
		name     string
		rules    []*sarif.ReportingDescriptor
		results  []*sarif.Result
		expected []string
	}{
		{
			name:     "a rule that describes nothing goes",
			rules:    rules,
			results:  []*sarif.Result{makeResult("b", sarif.LevelError, "", nil)},
			expected: []string{"b"},
		},
		{
			name:     "the rules behind the results stay",
			rules:    rules,
			results:  []*sarif.Result{makeResult("a", sarif.LevelError, "", nil), makeResult("c", sarif.LevelNote, "", nil)},
			expected: []string{"a", "c"},
		},
		{name: "nothing survived the filter", rules: rules, results: nil, expected: nil},
		{name: "no rules to prune", rules: nil, results: nil, expected: nil},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			var got []string
			for _, rule := range pruneRules(testCase.rules, testCase.results) {
				got = append(got, rule.Id)
			}

			if !reflect.DeepEqual(got, testCase.expected) {
				t.Errorf("pruneRules = %v, want %v", got, testCase.expected)
			}
		})
	}
}

func TestTruncate(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		text     string
		width    int
		expected string
	}{
		{name: "shorter than the width is left alone", text: "abc", width: 5, expected: "abc"},
		{name: "exactly the width is left alone", text: "abcde", width: 5, expected: "abcde"},
		{name: "longer is cut and says so", text: "abcdefgh", width: 5, expected: "abcd…"},
		{name: "the space before the cut goes with it", text: "ab cdefgh", width: 4, expected: "ab…"},
		{name: "no room to say anything", text: "abcdef", width: 1, expected: "…"},
		{name: "no room at all", text: "abcdef", width: 0, expected: "…"},
		{name: "a rune is not cut in half", text: "åäöéèü", width: 4, expected: "åäö…"},
		{name: "empty", text: "", width: 5, expected: ""},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := truncate(testCase.text, testCase.width); got != testCase.expected {
				t.Errorf("truncate(%q, %d) = %q, want %q", testCase.text, testCase.width, got, testCase.expected)
			}
		})
	}
}

func TestWrap(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		text     string
		width    int
		expected []string
	}{
		{name: "fits on one line", text: "a bb ccc", width: 10, expected: []string{"a bb ccc"}},
		{name: "breaks on the spaces", text: "aaa bbb ccc", width: 7, expected: []string{"aaa bbb", "ccc"}},
		{
			name:     "a word longer than the width overruns rather than being cut",
			text:     "see https://example.com/a/very/long/path now",
			width:    10,
			expected: []string{"see", "https://example.com/a/very/long/path", "now"},
		},
		{name: "runs of whitespace collapse", text: "aaa   bbb\n\nccc", width: 20, expected: []string{"aaa bbb ccc"}},
		{name: "empty", text: "", width: 10, expected: nil},
		{name: "whitespace only", text: "   \n ", width: 10, expected: nil},
		{name: "a width of nothing gives up rather than looping", text: "aa bb", width: 0, expected: []string{"aa", "bb"}},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			got := wrap(testCase.text, testCase.width)
			if !reflect.DeepEqual(got, testCase.expected) {
				t.Fatalf("wrap(%q, %d) = %v, want %v", testCase.text, testCase.width, got, testCase.expected)
			}

			for _, line := range got {
				// A line of one word is allowed to overrun; a line of several is not, having had
				// somewhere to break.
				if len(line) > testCase.width && strings.Contains(line, " ") {
					t.Errorf("wrap(%q, %d) produced %q, longer than the width", testCase.text, testCase.width, line)
				}
			}
		})
	}
}

func TestWriteReport(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		results []*sarif.Result
		// expected are the substrings the report must carry.
		expected []string
		// unexpected are the ones it must not.
		unexpected []string
	}{
		{
			name:     "nothing found says so rather than saying nothing",
			results:  nil,
			expected: []string{"No findings."},
		},
		{
			name: "a finding gives its level, its header, its rule and its reason",
			results: []*sarif.Result{
				makeResult(
					"missing_x_content_type_options",
					sarif.LevelError,
					"The X-Content-Type-Options header should be set to a value of \"nosniff\".",
					sarif.PropertyBag{"headerName": "X-Content-Type-Options"},
				),
			},
			expected: []string{
				"error",
				"X-Content-Type-Options",
				"(missing_x_content_type_options)",
				"should be set to a value of \"nosniff\".",
			},
			unexpected: []string{"value:"},
		},
		{
			name: "the value it was raised on is shown",
			results: []*sarif.Result{
				makeResult(
					"x_content_type_options_bad_value",
					sarif.LevelError,
					"Bad value.",
					sarif.PropertyBag{"headerName": "X-Content-Type-Options", "headerValue": "sniff"},
				),
			},
			expected: []string{"value: sniff"},
		},
		{
			name: "a long value is cut to a line",
			results: []*sarif.Result{
				makeResult(
					"content_security_policy_unsafe_inline",
					sarif.LevelError,
					"Unsafe.",
					sarif.PropertyBag{
						"headerName":  "Content-Security-Policy",
						"headerValue": strings.Repeat("default-src 'self'; ", 20),
					},
				),
			},
			expected: []string{"value: default-src 'self';", "…"},
		},
		{
			name: "a property that is not text is left out rather than printed as whatever it is",
			results: []*sarif.Result{
				makeResult("r", sarif.LevelNote, "Reason.", sarif.PropertyBag{"headerName": 42}),
			},
			expected:   []string{"(r)", "Reason."},
			unexpected: []string{"42"},
		},
		{
			name: "findings are separated",
			results: []*sarif.Result{
				makeResult("first", sarif.LevelError, "One.", nil),
				makeResult("second", sarif.LevelNote, "Two.", nil),
			},
			expected: []string{"(first)", "(second)", "\n\n"},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			var buffer bytes.Buffer

			if err := writeReport(&buffer, testCase.results); err != nil {
				t.Fatalf("writeReport error = %v", err)
			}

			report := buffer.String()

			for _, expected := range testCase.expected {
				if !strings.Contains(report, expected) {
					t.Errorf("report does not carry %q:\n%s", expected, report)
				}
			}

			for _, unexpected := range testCase.unexpected {
				if strings.Contains(report, unexpected) {
					t.Errorf("report carries %q, which it should not:\n%s", unexpected, report)
				}
			}

			for _, line := range strings.Split(report, "\n") {
				if len([]rune(line)) > reportWidth {
					t.Errorf("line is wider than the report: %q", line)
				}
			}
		})
	}
}
