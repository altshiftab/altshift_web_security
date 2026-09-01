package x_content_type_options

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
	var results []*sarif.Result

	if headerValue != "nosniff" {
		results = append(results, httpHeadersSecurityCheckerInternal.MakeRuleIdResult(rule_id.XContentTypeOptionsBadValue))
	}

	return results
}
