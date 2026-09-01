package rule_id_mappings

import (
	"testing"
)

// knownSeverities are the values a rule may carry. Both tables are keyed and valued
// by defined string types, so a rule id put where a severity belongs compiles and
// then falls through the level mapping to the least level there is -- the rule is
// emitted, but silently, at a level saying the finding does not matter.
var knownSeverities = map[Severity]struct{}{
	SeverityHigh:   {},
	SeverityMedium: {},
	SeverityLow:    {},
	SeverityInfo:   {},
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

// Every rule that can be raised needs a severity to be emitted at, a title to head
// it with, and a description saying why it matters.
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
				text, found := testCase.table[ruleId]
				if !found {
					t.Errorf("rule %q has a severity but no %s", ruleId, testCase.name)

					continue
				}

				if text == "" {
					t.Errorf("rule %q has an empty %s", ruleId, testCase.name)
				}
			}
		})
	}
}

// The reverse: a rule described but never given a severity would be emitted at the
// least level there is, whatever its text says.
func TestEveryDescribedRuleHasASeverity(t *testing.T) {
	t.Parallel()

	for ruleId := range RuleIdToDescription {
		if _, found := RuleIdToSeverity[ruleId]; !found {
			t.Errorf("rule %q is described but has no severity", ruleId)
		}
	}
}
