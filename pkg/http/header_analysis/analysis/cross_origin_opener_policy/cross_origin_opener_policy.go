package cross_origin_opener_policy

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

	headerValue = strings.ToLower(headerValue)

	if headerValue == "unsafe-none" {
		return []*sarif.Result{
			httpHeadersSecurityCheckerInternal.MakeRuleIdResult(rule_id.CrossOriginOpenerPolicyUnsafeNone),
		}
	}
	if headerValue != "same-origin" {
		return []*sarif.Result{
			httpHeadersSecurityCheckerInternal.MakeRuleIdResult(rule_id.CrossOriginOpenerPolicyBadValue),
		}
	}

	return nil
}
