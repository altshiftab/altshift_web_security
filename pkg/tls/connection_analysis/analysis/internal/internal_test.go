package internal

import (
	"testing"

	"github.com/altshiftab/altshift_web_security/pkg/tls/connection_analysis/rule_id"
	"github.com/altshiftab/altshift_web_security/pkg/tls/connection_analysis/rule_id_mappings"
	"github.com/altshiftab/altshift_web_security/pkg/tls/wire"
	"github.com/altshiftab/utils_go/pkg/sarif"
)

func TestSeverityToLevel(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		severity rule_id_mappings.Severity
		expected sarif.Level
	}{
		{name: "high", severity: rule_id_mappings.SeverityHigh, expected: sarif.LevelError},
		{name: "medium", severity: rule_id_mappings.SeverityMedium, expected: sarif.LevelWarning},
		{name: "low", severity: rule_id_mappings.SeverityLow, expected: sarif.LevelNote},
		{name: "info", severity: rule_id_mappings.SeverityInfo, expected: sarif.LevelNone},
		{
			// A severity outside the vocabulary must land on a level SARIF
			// defines, rather than putting the raw value on the wire.
			name:     "a severity the mapping does not know",
			severity: rule_id_mappings.Severity("critical"),
			expected: sarif.LevelNone,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := SeverityToLevel(testCase.severity); got != testCase.expected {
				t.Errorf("SeverityToLevel(%q) = %q, want %q", testCase.severity, got, testCase.expected)
			}
		})
	}
}

// SARIF requires a result whose kind is not "fail" to carry level none, so the two
// constructors that build non-failures must always produce one.
func TestResultConstructors(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		result        *sarif.Result
		expectedKind  sarif.Kind
		expectedLevel sarif.Level
		expectedRule  string
	}{
		{
			name:          "a finding",
			result:        MakeResult(rule_id.CompressionEnabled),
			expectedKind:  sarif.KindFail,
			expectedLevel: sarif.LevelError,
			expectedRule:  rule_id.CompressionEnabled,
		},
		{
			name:          "a check that could not be run",
			result:        MakeNotDeterminedResult("0-RTT", "the ticket could not be read"),
			expectedKind:  sarif.KindOpen,
			expectedLevel: sarif.LevelNone,
			expectedRule:  rule_id.CheckNotDetermined,
		},
		{
			name:          "a check with no subject",
			result:        MakeNotApplicableResult("TLS compression", "the server speaks only TLS 1.3"),
			expectedKind:  sarif.KindNotApplicable,
			expectedLevel: sarif.LevelNone,
			expectedRule:  rule_id.CheckNotDetermined,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if testCase.result.Kind != testCase.expectedKind {
				t.Errorf("kind = %q, want %q", testCase.result.Kind, testCase.expectedKind)
			}

			if testCase.result.Level != testCase.expectedLevel {
				t.Errorf("level = %q, want %q", testCase.result.Level, testCase.expectedLevel)
			}

			if testCase.result.RuleId != testCase.expectedRule {
				t.Errorf("rule id = %q, want %q", testCase.result.RuleId, testCase.expectedRule)
			}

			if testCase.result.Message == nil || testCase.result.Message.Text == "" {
				t.Error("the result carries no message")
			}

			if _, found := testCase.result.Properties["subject"]; !found {
				t.Error("the result carries no subject, so a report has nothing to head it with")
			}
		})
	}
}

func TestWithProperty(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		result *sarif.Result
	}{
		{name: "a result with no properties yet", result: &sarif.Result{RuleId: "r"}},
		{name: "a result that already has some", result: MakeResult(rule_id.CompressionEnabled)},
		{name: "no result at all", result: nil},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			got := WithProperty(testCase.result, "group", "x25519")

			if testCase.result == nil {
				if got != nil {
					t.Error("a property was added to nothing")
				}

				return
			}

			if value, _ := got.Properties["group"].(string); value != "x25519" {
				t.Errorf("group = %q, want x25519", value)
			}
		})
	}
}

func TestNames(t *testing.T) {
	t.Parallel()

	t.Run("suite names are sorted so a report is reproducible", func(t *testing.T) {
		t.Parallel()

		names := SuiteNames([]uint16{0xc030, 0xc02f})

		if len(names) != 2 || names[0] > names[1] {
			t.Errorf("SuiteNames = %v, want two names in order", names)
		}
	})

	t.Run("version names run newest first", func(t *testing.T) {
		t.Parallel()

		names := VersionNames([]uint16{wire.VersionTls10, wire.VersionTls13, wire.VersionTls12})

		expected := []string{"TLS 1.3", "TLS 1.2", "TLS 1.0"}
		for index, want := range expected {
			if names[index] != want {
				t.Errorf("VersionNames[%d] = %q, want %q", index, names[index], want)
			}
		}
	})
}
