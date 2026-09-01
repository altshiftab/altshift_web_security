package x_frame_options

import (
	"strings"

	httpHeadersSecurityCheckerInternal "github.com/altshiftab/altshift_web_security/pkg/http/header_analysis/analysis/internal"
	"github.com/altshiftab/altshift_web_security/pkg/http/header_analysis/rule_id"
	"github.com/altshiftab/utils_go/pkg/sarif"
)

func Analyze(headerValue string) []*sarif.Result {
	if headerValue == "" {
		return nil
	}

	results := []*sarif.Result{
		httpHeadersSecurityCheckerInternal.MakeRuleIdResult(rule_id.XFrameOptionsObsolete),
	}

	uppercaseValue := strings.ToUpper(headerValue)
	if uppercaseValue != "DENY" && uppercaseValue != "SAMEORIGIN" {
		results = append(results, httpHeadersSecurityCheckerInternal.MakeRuleIdResult(rule_id.XFrameOptionsBadValue))
	}

	return results
}
