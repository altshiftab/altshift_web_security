package rule_id_mappings

import (
	"testing"
)

// knownSeverities are the values a rule may carry. A value outside them reaches
// internal.SeverityToLevel, which has nowhere to map it and falls through to the
// least level there is -- so a rule that carries one is emitted, but silently, at
// a level that says the finding does not matter.
//
// The tables are keyed and valued by defined string types, so a rule id put where
// a severity belongs is a mistake the compiler cannot see. This is the check that
// sees it.
var knownSeverities = map[Severity]struct{}{
	SeverityHigh:    {},
	SeverityMedium:  {},
	SeverityLow:     {},
	SeverityInfo:    {},
	SeverityDynamic: {},
}

func TestRuleIdToSeverityHoldsOnlySeverities(t *testing.T) {
	t.Parallel()

	for ruleId, severity := range RuleIdToSeverity {
		t.Run(ruleId, func(t *testing.T) {
			t.Parallel()

			if _, found := knownSeverities[severity]; !found {
				t.Errorf("rule %q carries severity %q, which is not one of the declared severities", ruleId, severity)
			}
		})
	}
}

// Every rule that can be raised needs a severity to be emitted at, and something
// to say for itself. A rule whose message is built where it is raised says so
// with the dynamic sentinel rather than by being absent.
func TestEveryRuleIsDescribed(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name  string
		table map[string]string
	}{
		{name: "title", table: RuleIdToTitle},
		{name: "description", table: RuleIdToDescription},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			for ruleId := range RuleIdToSeverity {
				if _, found := testCase.table[ruleId]; !found {
					t.Errorf("rule %q has a severity but no %s", ruleId, testCase.name)
				}
			}
		})
	}
}
