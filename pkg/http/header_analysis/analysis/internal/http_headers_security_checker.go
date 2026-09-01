package internal

import (
	"fmt"

	"github.com/altshiftab/altshift_web_security/pkg/http/header_analysis/rule_id"
	"github.com/altshiftab/altshift_web_security/pkg/http/header_analysis/rule_id_mappings"
	"github.com/altshiftab/utils_go/pkg/sarif"
)

// LevelDynamic marks rules whose level is decided by the analyzer at runtime
// (e.g. CSP findings whose severity depends on the directive). Helpers using
// this sentinel rely on the analyzer to overwrite Level before emission.
const LevelDynamic sarif.Level = "DYNAMIC"

// Local rule IDs for findings that don't yet have an entry in the root rule_id package.
const (
	RuleIdXXssProtectionObsolete          = "x_xss_protection_obsolete"
	RuleIdExpectCtDeprecated              = "expect_ct_deprecated"
	RuleIdPublicKeyPinsDeprecated         = "public_key_pins_deprecated"
	RuleIdServerHeaderExposure            = "server_header_exposure"
	RuleIdXPoweredByHeaderExposure        = "x_powered_by_header_exposure"
	RuleIdXAspNetVersionHeaderExposure    = "x_asp_net_version_header_exposure"
	RuleIdXAspNetMvcVersionHeaderExposure = "x_asp_net_mvc_version_header_exposure"
)

var levelOrder = map[sarif.Level]int{
	sarif.LevelNone:    0,
	sarif.LevelNote:    1,
	sarif.LevelWarning: 2,
	sarif.LevelError:   3,
}

// SeverityToLevel maps the project's severity vocabulary onto SARIF levels.
// info → none, low → note, medium → warning, high → error.
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
	case rule_id_mappings.SeverityDynamic:
		return LevelDynamic
	default:
		return sarif.LevelNone
	}
}

func headerProperties(headerName string, rawValue string) sarif.PropertyBag {
	props := sarif.PropertyBag{}
	if headerName != "" {
		props["headerName"] = headerName
	}
	if rawValue != "" {
		props["headerValue"] = rawValue
	}
	if len(props) == 0 {
		return nil
	}
	return props
}

func MakeExposureResult(ruleId string, headerName string, rawValue string) *sarif.Result {
	description := fmt.Sprintf(
		"The %s header potentially exposes system information that could provide attackers with clues about how to attack the system, and enable automated attacks. Exposing this header publicly is unwarranted.",
		headerName,
	)
	return &sarif.Result{
		RuleId:     ruleId,
		Level:      sarif.LevelNote,
		Message:    &sarif.Message{Text: description},
		Properties: headerProperties(headerName, rawValue),
	}
}

func MakeDeprecatedResult(ruleId string, headerName string, rawValue string) *sarif.Result {
	description := fmt.Sprintf(
		"The %s header is considered deprecated by browsers and should no longer be used.",
		headerName,
	)
	return &sarif.Result{
		RuleId:     ruleId,
		Level:      sarif.LevelNone,
		Message:    &sarif.Message{Text: description},
		Properties: headerProperties(headerName, rawValue),
	}
}

func MakeObsoleteResult(ruleId string, headerName string, rawValue string) *sarif.Result {
	description := fmt.Sprintf(
		"Support for %s has been removed from browsers and its use can now be considered obsolete.",
		headerName,
	)
	return &sarif.Result{
		RuleId:     ruleId,
		Level:      sarif.LevelNone,
		Message:    &sarif.Message{Text: description},
		Properties: headerProperties(headerName, rawValue),
	}
}

func MakeMissingResult(ruleId string, headerName string) *sarif.Result {
	description := rule_id_mappings.RuleIdToDescription[ruleId]
	if description == "" {
		description = fmt.Sprintf("The %s header is missing.", headerName)
	}
	return &sarif.Result{
		RuleId:     ruleId,
		Level:      SeverityToLevel(rule_id_mappings.RuleIdToSeverity[ruleId]),
		Message:    &sarif.Message{Text: description},
		Properties: headerProperties(headerName, ""),
	}
}

func MakeRuleIdResult(ruleId string) *sarif.Result {
	return &sarif.Result{
		RuleId:  ruleId,
		Level:   SeverityToLevel(rule_id_mappings.RuleIdToSeverity[ruleId]),
		Message: &sarif.Message{Text: rule_id_mappings.RuleIdToDescription[ruleId]},
	}
}

func MakeMultipleHeadersResult(headerName string, rawValue string, level sarif.Level) *sarif.Result {
	description := rule_id_mappings.RuleIdToDescription[rule_id.MultipleHeaderValuesRuleId]
	return &sarif.Result{
		RuleId:     rule_id.MultipleHeaderValuesRuleId,
		Level:      level,
		Message:    &sarif.Message{Text: description},
		Properties: headerProperties(headerName, rawValue),
	}
}

func GetMultipleHeadersLevelWithErr(
	headerValues []string,
	analyze func(string) ([]*sarif.Result, error),
) (sarif.Level, error) {
	worst := sarif.LevelNone
	for _, headerValue := range headerValues {
		results, err := analyze(headerValue)
		if err != nil {
			return "", err
		}
		for _, result := range results {
			if levelOrder[result.Level] > levelOrder[worst] {
				worst = result.Level
			}
		}
	}
	return worst, nil
}

func GetMultipleHeadersLevel(headerValues []string, analyze func(string) []*sarif.Result) sarif.Level {
	level, _ := GetMultipleHeadersLevelWithErr(
		headerValues,
		func(headerValue string) ([]*sarif.Result, error) {
			return analyze(headerValue), nil
		},
	)
	return level
}
