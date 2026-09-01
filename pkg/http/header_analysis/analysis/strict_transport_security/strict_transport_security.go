package strict_transport_security

import (
	"fmt"

	httpHeadersSecurityCheckerInternal "github.com/altshiftab/altshift_web_security/pkg/http/header_analysis/analysis/internal"
	"github.com/altshiftab/altshift_web_security/pkg/http/header_analysis/rule_id"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/http/types/strict_transport_security"
	"github.com/altshiftab/utils_go/pkg/sarif"
)

func Analyze(headerValue string) ([]*sarif.Result, error) {
	if headerValue == "" {
		return nil, nil
	}

	data := []byte(headerValue)
	strictTransportSecurityPolicy, err := strict_transport_security.Parse(data)
	if err != nil {
		if altshiftErrors.IsAny(err, altshiftErrors.ErrSyntaxError, altshiftErrors.ErrSemanticError) {
			return []*sarif.Result{
				httpHeadersSecurityCheckerInternal.MakeRuleIdResult(rule_id.InvalidStrictTransportSecurity),
			}, nil
		}

		return nil, altshiftErrors.New(fmt.Errorf("parse strict transport security: %w", err), data)
	}

	// Parse reports a header whose directive name it cannot resolve as
	// (nil, nil), so a nil policy without an error is reachable. Treat it as an
	// invalid policy - the same as a syntax error - rather than dereferencing it.
	if strictTransportSecurityPolicy == nil {
		return []*sarif.Result{
			httpHeadersSecurityCheckerInternal.MakeRuleIdResult(rule_id.InvalidStrictTransportSecurity),
		}, nil
	}

	var results []*sarif.Result

	if strictTransportSecurityPolicy.MaxAge < 31536000 {
		results = append(
			results,
			httpHeadersSecurityCheckerInternal.MakeRuleIdResult(rule_id.StrictTransportSecurityMissingOrLowMaxAge),
		)
	}

	if !strictTransportSecurityPolicy.IncludeSubdomains {
		results = append(
			results,
			httpHeadersSecurityCheckerInternal.MakeRuleIdResult(rule_id.StrictTransportSecurityMissingIncludeSubdomains),
		)
	}

	if !strictTransportSecurityPolicy.Preload {
		results = append(
			results,
			httpHeadersSecurityCheckerInternal.MakeRuleIdResult(rule_id.StrictTransportSecurityMissingPreload),
		)
	}

	return results, nil
}
