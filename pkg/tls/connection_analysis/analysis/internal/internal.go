// Package internal holds what the per-check analyzers share: the mapping from the
// policy's severity vocabulary onto SARIF levels, and the constructors that build a
// result from a rule id.
package internal

import (
	"fmt"
	"sort"

	"github.com/altshiftab/altshift_web_security/pkg/tls/cipher_suite"
	"github.com/altshiftab/altshift_web_security/pkg/tls/connection_analysis/rule_id"
	"github.com/altshiftab/altshift_web_security/pkg/tls/connection_analysis/rule_id_mappings"
	"github.com/altshiftab/altshift_web_security/pkg/tls/wire"
	"github.com/altshiftab/utils_go/pkg/sarif"
)

// subjectProperty names the property a report heads a finding with: the header it
// was raised on, or -- for a check that is not about a header -- what it is about.
const subjectProperty = "subject"

// SeverityToLevel maps the policy's severity vocabulary onto SARIF levels.
// info -> none, low -> note, medium -> warning, high -> error.
func SeverityToLevel(severity rule_id_mappings.Severity) sarif.Level {
	switch severity {
	case rule_id_mappings.SeverityHigh:
		return sarif.LevelError
	case rule_id_mappings.SeverityMedium:
		return sarif.LevelWarning
	case rule_id_mappings.SeverityLow:
		return sarif.LevelNote
	case rule_id_mappings.SeverityInfo:
		return sarif.LevelNone
	default:
		return sarif.LevelNone
	}
}

// MakeResult builds the finding for a rule, at the level the policy gives it.
func MakeResult(ruleId string) *sarif.Result {
	return &sarif.Result{
		RuleId:  ruleId,
		Kind:    sarif.KindFail,
		Level:   SeverityToLevel(rule_id_mappings.RuleIdToSeverity[ruleId]),
		Message: &sarif.Message{Text: rule_id_mappings.RuleIdToDescription[ruleId]},
		Properties: sarif.PropertyBag{
			subjectProperty: rule_id_mappings.RuleIdToTitle[ruleId],
		},
	}
}

// MakeNotDeterminedResult says a check was not run and why.
//
// Silence would be read as a pass, which is the one thing it must not mean. SARIF
// requires a result whose kind is not "fail" to carry level none, so this is
// reported as an open question at level none rather than as a finding.
func MakeNotDeterminedResult(check string, reason string) *sarif.Result {
	return &sarif.Result{
		RuleId: rule_id.CheckNotDetermined,
		Kind:   sarif.KindOpen,
		Level:  sarif.LevelNone,
		Message: &sarif.Message{
			Text: fmt.Sprintf("The %s check could not be completed: %s. It is not a pass.", check, reason),
		},
		Properties: sarif.PropertyBag{
			subjectProperty: "Undetermined: " + check,
			"check":         check,
			"reason":        reason,
		},
	}
}

// MakeNotApplicableResult says a check has no subject on this server -- compression
// against a server that speaks only TLS 1.3, which has none to enable.
func MakeNotApplicableResult(check string, reason string) *sarif.Result {
	return &sarif.Result{
		RuleId: rule_id.CheckNotDetermined,
		Kind:   sarif.KindNotApplicable,
		Level:  sarif.LevelNone,
		Message: &sarif.Message{
			Text: fmt.Sprintf("The %s check does not apply to this server: %s.", check, reason),
		},
		Properties: sarif.PropertyBag{
			subjectProperty: "Not applicable: " + check,
			"check":         check,
			"reason":        reason,
		},
	}
}

// WithProperty adds a property, which is how a result carries the particulars behind
// it: which suites, which group, which version.
func WithProperty(result *sarif.Result, name string, value any) *sarif.Result {
	if result == nil {
		return nil
	}

	if result.Properties == nil {
		result.Properties = sarif.PropertyBag{}
	}

	result.Properties[name] = value

	return result
}

// WithMessage replaces the rule's stock description with one naming the particulars.
// The stock text is kept as the rule's description in the rule table, so nothing is
// lost by saying something more specific here.
func WithMessage(result *sarif.Result, text string) *sarif.Result {
	if result == nil {
		return nil
	}

	result.Message = &sarif.Message{Text: text}

	return result
}

// SuiteNames turns wire values into the names a report should use, in a stable
// order.
func SuiteNames(ids []uint16) []string {
	names := make([]string, 0, len(ids))
	for _, id := range ids {
		names = append(names, cipher_suite.Name(id))
	}

	sort.Strings(names)

	return names
}

// VersionNames does the same for protocol versions, newest first.
func VersionNames(versions []uint16) []string {
	sorted := make([]uint16, len(versions))
	copy(sorted, versions)
	sort.Slice(sorted, func(i int, j int) bool { return sorted[i] > sorted[j] })

	names := make([]string, 0, len(sorted))
	for _, version := range sorted {
		names = append(names, wire.VersionName(version))
	}

	return names
}
