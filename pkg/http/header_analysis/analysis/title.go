package analysis

import (
	"fmt"
	"strings"

	httpHeadersSecurityCheckerInternal "github.com/altshiftab/altshift_web_security/pkg/http/header_analysis/analysis/internal"
	"github.com/altshiftab/altshift_web_security/pkg/http/header_analysis/rule_id"
	"github.com/altshiftab/altshift_web_security/pkg/http/header_analysis/rule_id_mappings"
	"github.com/altshiftab/utils_go/pkg/sarif"
)

// Title is what a result is called, short enough to head a finding, where its message is the
// explanation beneath it.
//
// The curated title is used where the rule has one. A rule built for the header it was found on --
// an exposing, deprecated or obsolete header, or one sent more than once -- has none, and is named
// after the header. A rule whose wording depends on what was found has a placeholder where its title
// would be, and is called by the first sentence of its message, which says what was found.
func Title(result *sarif.Result) string {
	if result == nil {
		return ""
	}

	headerName, _ := result.Properties["headerName"].(string)
	if headerName == "" {
		headerName = "A"
	} else {
		headerName = "The " + headerName
	}

	switch result.RuleId {
	case httpHeadersSecurityCheckerInternal.RuleIdServerHeaderExposure,
		httpHeadersSecurityCheckerInternal.RuleIdXPoweredByHeaderExposure,
		httpHeadersSecurityCheckerInternal.RuleIdXAspNetVersionHeaderExposure,
		httpHeadersSecurityCheckerInternal.RuleIdXAspNetMvcVersionHeaderExposure:
		return fmt.Sprintf("%s header exposes system information", headerName)
	case httpHeadersSecurityCheckerInternal.RuleIdExpectCtDeprecated,
		httpHeadersSecurityCheckerInternal.RuleIdPublicKeyPinsDeprecated:
		return fmt.Sprintf("%s header is deprecated", headerName)
	case httpHeadersSecurityCheckerInternal.RuleIdXXssProtectionObsolete:
		return fmt.Sprintf("%s header is obsolete", headerName)
	case rule_id.MultipleHeaderValuesRuleId:
		return fmt.Sprintf("%s header is set more than once", headerName)
	}

	if title := rule_id_mappings.RuleIdToTitle[result.RuleId]; title != "" &&
		title != string(rule_id_mappings.SeverityDynamic) {
		return title
	}

	if result.Message != nil {
		if sentence := firstSentence(result.Message.Text); sentence != "" {
			return sentence
		}
	}

	return result.RuleId
}

// firstSentence is the text up to its first full stop, without the stop.
func firstSentence(text string) string {
	text = strings.TrimSpace(text)
	if index := strings.Index(text, ". "); index >= 0 {
		text = text[:index]
	}

	return strings.TrimSuffix(text, ".")
}
