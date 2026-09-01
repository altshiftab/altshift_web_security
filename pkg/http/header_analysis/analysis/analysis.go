package analysis

import (
	"fmt"
	"net/http"
	"slices"
	"strings"

	contentSecurityPolicyAnalysis "github.com/altshiftab/altshift_web_security/pkg/http/header_analysis/analysis/content_security_policy"
	"github.com/altshiftab/altshift_web_security/pkg/http/header_analysis/analysis/cross_origin_embedder_policy"
	"github.com/altshiftab/altshift_web_security/pkg/http/header_analysis/analysis/cross_origin_opener_policy"
	"github.com/altshiftab/altshift_web_security/pkg/http/header_analysis/analysis/cross_origin_resource_policy"
	httpHeadersSecurityCheckerInternal "github.com/altshiftab/altshift_web_security/pkg/http/header_analysis/analysis/internal"
	"github.com/altshiftab/altshift_web_security/pkg/http/header_analysis/analysis/referrer_policy"
	strictTransportSecurityAnalysis "github.com/altshiftab/altshift_web_security/pkg/http/header_analysis/analysis/strict_transport_security"
	"github.com/altshiftab/altshift_web_security/pkg/http/header_analysis/analysis/x_content_type_options"
	"github.com/altshiftab/altshift_web_security/pkg/http/header_analysis/analysis/x_frame_options"
	"github.com/altshiftab/altshift_web_security/pkg/http/header_analysis/rule_id"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/sarif"
)

const (
	ToolName           = "http_headers_security_checker"
	ToolInformationUri = "https://github.com/altshiftab/altshift_web_security"
)

// responseHasBody guesses whether the response carries a body based on the
// presence of body-indicating headers. It is intentionally conservative: a body
// is assumed only when at least one of Content-Length (non-zero), Transfer-
// Encoding, or Content-Type is set. A response that lacks all three (typical of
// a bare 3xx redirect, 204 No Content, or 304 Not Modified) is treated as
// having no body.
func responseHasBody(header http.Header) bool {
	if header.Get("Content-Length") == "0" {
		return false
	}
	if header.Get("Content-Length") != "" {
		return true
	}
	if header.Get("Transfer-Encoding") != "" {
		return true
	}
	if header.Get("Content-Type") != "" {
		return true
	}
	return false
}

// downgradeIfNoBody downgrades each result's level to LevelNone when the
// response has no body. Document-context headers (CSP, COOP, COEP,
// Permissions-Policy) don't apply when there is no document to protect.
func downgradeIfNoBody(results []*sarif.Result, hasBody bool) []*sarif.Result {
	if hasBody {
		return results
	}
	for _, result := range results {
		if result != nil {
			result.Level = sarif.LevelNone
		}
	}
	return results
}

func setHeaderProperty(result *sarif.Result, headerName string, rawValue string) *sarif.Result {
	if result == nil {
		return nil
	}
	if result.Properties == nil {
		result.Properties = sarif.PropertyBag{}
	}
	if headerName != "" {
		result.Properties["headerName"] = headerName
	}
	if rawValue != "" {
		result.Properties["headerValue"] = rawValue
	}
	if len(result.Properties) == 0 {
		result.Properties = nil
	}
	return result
}

func annotateResults(results []*sarif.Result, headerName string, rawValue string) []*sarif.Result {
	for _, r := range results {
		setHeaderProperty(r, headerName, rawValue)
	}
	return results
}

func AnalyzeHeaders(header http.Header) (*sarif.Run, error) {
	if header == nil {
		return nil, nil
	}

	hasBody := responseHasBody(header)

	// Iterate header names in deterministic order so results ordering is stable.
	headerNames := []string{
		"X-Frame-Options",
		"X-XSS-Protection",
		"X-Content-Type-Options",
		"Referrer-Policy",
		"Strict-Transport-Security",
		"Expect-CT",
		"Content-Security-Policy",
		"Cross-Origin-Opener-Policy",
		"Cross-Origin-Embedder-Policy",
		"Cross-Origin-Resource-Policy",
		"Permissions-Policy",
		"Server",
		"X-Powered-By",
		"Feature-Policy",
		"Public-Key-Pins",
		"X-AspNet-Version",
		"X-AspNetMvc-Version",
	}
	slices.Sort(headerNames)

	var allResults []*sarif.Result

	for _, headerName := range headerNames {
		headerValues := header.Values(headerName)
		var firstHeaderValue string

		multipleHeaderValuesRaw := strings.Join(headerValues, ", ")

		if len(headerValues) == 1 {
			firstHeaderValue = headerValues[0]
		}

		var headerResults []*sarif.Result

		// TODO: Add `Set-Cookie` check?
		// TODO: Add `Location` check, too see if redirected to registered domain first rather than `www` etc.
		switch headerName {
		case "X-Frame-Options":
			analyzeFunc := x_frame_options.Analyze
			if len(headerValues) > 1 {
				headerResults = []*sarif.Result{
					httpHeadersSecurityCheckerInternal.MakeMultipleHeadersResult(
						headerName,
						multipleHeaderValuesRaw,
						httpHeadersSecurityCheckerInternal.GetMultipleHeadersLevel(headerValues, analyzeFunc),
					),
				}
				break
			}

			if len(headerValues) != 0 {
				headerResults = annotateResults(analyzeFunc(firstHeaderValue), headerName, firstHeaderValue)
			}
		case "X-XSS-Protection":
			if len(headerValues) != 0 {
				headerResults = []*sarif.Result{
					httpHeadersSecurityCheckerInternal.MakeObsoleteResult(
						httpHeadersSecurityCheckerInternal.RuleIdXXssProtectionObsolete,
						headerName,
						firstHeaderValue,
					),
				}
			}
		case "X-Content-Type-Options":
			if len(headerValues) == 0 {
				headerResults = []*sarif.Result{
					httpHeadersSecurityCheckerInternal.MakeMissingResult(rule_id.MissingXContentTypeOptions, headerName),
				}
				break
			}

			analyzeFunc := x_content_type_options.Analyze
			if len(headerValues) > 1 {
				headerResults = []*sarif.Result{
					httpHeadersSecurityCheckerInternal.MakeMultipleHeadersResult(
						headerName,
						multipleHeaderValuesRaw,
						httpHeadersSecurityCheckerInternal.GetMultipleHeadersLevel(headerValues, analyzeFunc),
					),
				}
				break
			}

			headerResults = annotateResults(analyzeFunc(firstHeaderValue), headerName, firstHeaderValue)
		case "Referrer-Policy":
			if len(headerValues) == 0 {
				// `strict-origin-when-cross-origin` is the recommended value and is the default.
				continue
			}

			analyzeFunc := referrer_policy.Analyze
			if len(headerValues) > 1 {
				headerResults = []*sarif.Result{
					httpHeadersSecurityCheckerInternal.MakeMultipleHeadersResult(
						headerName,
						multipleHeaderValuesRaw,
						httpHeadersSecurityCheckerInternal.GetMultipleHeadersLevel(headerValues, analyzeFunc),
					),
				}
				break
			}

			headerResults = annotateResults(analyzeFunc(firstHeaderValue), headerName, firstHeaderValue)
		case "Strict-Transport-Security":
			if len(headerValues) == 0 {
				headerResults = []*sarif.Result{
					httpHeadersSecurityCheckerInternal.MakeMissingResult(rule_id.MissingStrictTransportSecurity, headerName),
				}
				break
			}

			analyzeFunc := strictTransportSecurityAnalysis.Analyze
			if len(headerValues) > 1 {
				level, err := httpHeadersSecurityCheckerInternal.GetMultipleHeadersLevelWithErr(headerValues, analyzeFunc)
				if err != nil {
					return nil, altshiftErrors.New(
						fmt.Errorf("get multiple headers level with err (strict transport security): %w", err),
						headerValues,
						analyzeFunc,
					)
				}
				headerResults = []*sarif.Result{
					httpHeadersSecurityCheckerInternal.MakeMultipleHeadersResult(headerName, multipleHeaderValuesRaw, level),
				}
				break
			}

			results, err := analyzeFunc(firstHeaderValue)
			if err != nil {
				return nil, altshiftErrors.New(
					fmt.Errorf("analyze func (strict transport security): %w", err),
					firstHeaderValue,
				)
			}
			headerResults = annotateResults(results, headerName, firstHeaderValue)
		case "Expect-CT":
			if len(headerValues) != 0 {
				headerResults = []*sarif.Result{
					httpHeadersSecurityCheckerInternal.MakeDeprecatedResult(
						httpHeadersSecurityCheckerInternal.RuleIdExpectCtDeprecated,
						headerName,
						multipleHeaderValuesRaw,
					),
				}
			}
		case "Content-Security-Policy":
			if len(headerValues) == 0 {
				headerResults = downgradeIfNoBody(
					[]*sarif.Result{
						httpHeadersSecurityCheckerInternal.MakeMissingResult(rule_id.MissingContentSecurityPolicy, headerName),
					},
					hasBody,
				)
				break
			}

			analyzeFunc := func(headerValue string) ([]*sarif.Result, error) {
				return contentSecurityPolicyAnalysis.Analyze(headerValue)
			}
			if len(headerValues) > 1 {
				level, err := httpHeadersSecurityCheckerInternal.GetMultipleHeadersLevelWithErr(headerValues, analyzeFunc)
				if err != nil {
					return nil, altshiftErrors.New(
						fmt.Errorf("get multiple headers level with err (content security policy): %w", err),
						headerValues,
						analyzeFunc,
					)
				}
				headerResults = []*sarif.Result{
					httpHeadersSecurityCheckerInternal.MakeMultipleHeadersResult(headerName, multipleHeaderValuesRaw, level),
				}
				break
			}

			results, err := analyzeFunc(firstHeaderValue)
			if err != nil {
				return nil, altshiftErrors.New(
					fmt.Errorf("analyze func (content security policy): %w", err),
					firstHeaderValue,
				)
			}
			headerResults = annotateResults(results, headerName, firstHeaderValue)
		case "Cross-Origin-Opener-Policy":
			if len(headerValues) == 0 {
				headerResults = downgradeIfNoBody(
					[]*sarif.Result{
						httpHeadersSecurityCheckerInternal.MakeMissingResult(rule_id.MissingCrossOriginOpenerPolicy, headerName),
					},
					hasBody,
				)
				break
			}

			analyzeFunc := cross_origin_opener_policy.Analyze
			if len(headerValues) > 1 {
				headerResults = []*sarif.Result{
					httpHeadersSecurityCheckerInternal.MakeMultipleHeadersResult(
						headerName,
						multipleHeaderValuesRaw,
						httpHeadersSecurityCheckerInternal.GetMultipleHeadersLevel(headerValues, analyzeFunc),
					),
				}
				break
			}

			headerResults = annotateResults(analyzeFunc(firstHeaderValue), headerName, firstHeaderValue)
		case "Cross-Origin-Embedder-Policy":
			if len(headerValues) == 0 {
				headerResults = downgradeIfNoBody(
					[]*sarif.Result{
						httpHeadersSecurityCheckerInternal.MakeMissingResult(rule_id.MissingCrossOriginEmbedderPolicy, headerName),
					},
					hasBody,
				)
				break
			}

			analyzeFunc := cross_origin_embedder_policy.Analyze
			if len(headerValues) > 1 {
				headerResults = []*sarif.Result{
					httpHeadersSecurityCheckerInternal.MakeMultipleHeadersResult(
						headerName,
						multipleHeaderValuesRaw,
						httpHeadersSecurityCheckerInternal.GetMultipleHeadersLevel(headerValues, analyzeFunc),
					),
				}
				break
			}

			headerResults = annotateResults(analyzeFunc(firstHeaderValue), headerName, firstHeaderValue)
		case "Cross-Origin-Resource-Policy":
			if len(headerValues) == 0 {
				headerResults = []*sarif.Result{
					httpHeadersSecurityCheckerInternal.MakeMissingResult(rule_id.MissingCrossOriginResourcePolicy, headerName),
				}
				break
			}

			analyzeFunc := cross_origin_resource_policy.Analyze
			if len(headerValues) > 1 {
				headerResults = []*sarif.Result{
					httpHeadersSecurityCheckerInternal.MakeMultipleHeadersResult(
						headerName,
						multipleHeaderValuesRaw,
						httpHeadersSecurityCheckerInternal.GetMultipleHeadersLevel(headerValues, analyzeFunc),
					),
				}
				break
			}

			headerResults = annotateResults(analyzeFunc(firstHeaderValue), headerName, firstHeaderValue)
		case "Permissions-Policy":
			if len(headerValues) == 0 {
				headerResults = downgradeIfNoBody(
					[]*sarif.Result{
						httpHeadersSecurityCheckerInternal.MakeMissingResult(rule_id.MissingPermissionsPolicy, headerName),
					},
					hasBody,
				)
				break
			}

			if len(headerValues) > 1 {
				headerResults = []*sarif.Result{
					httpHeadersSecurityCheckerInternal.MakeMultipleHeadersResult(headerName, multipleHeaderValuesRaw, sarif.LevelNote),
				}
			}
		case "Server":
			if len(headerValues) != 0 {
				headerResults = []*sarif.Result{
					httpHeadersSecurityCheckerInternal.MakeExposureResult(
						httpHeadersSecurityCheckerInternal.RuleIdServerHeaderExposure,
						headerName,
						multipleHeaderValuesRaw,
					),
				}
			}
		case "X-Powered-By":
			if len(headerValues) != 0 {
				headerResults = []*sarif.Result{
					httpHeadersSecurityCheckerInternal.MakeExposureResult(
						httpHeadersSecurityCheckerInternal.RuleIdXPoweredByHeaderExposure,
						headerName,
						multipleHeaderValuesRaw,
					),
				}
			}
		case "Feature-Policy":
			if len(headerValues) != 0 {
				result := httpHeadersSecurityCheckerInternal.MakeRuleIdResult(rule_id.FeaturePolicyObsolete)
				headerResults = []*sarif.Result{setHeaderProperty(result, headerName, firstHeaderValue)}
			}
		case "Public-Key-Pins":
			if len(headerValues) != 0 {
				headerResults = []*sarif.Result{
					httpHeadersSecurityCheckerInternal.MakeDeprecatedResult(
						httpHeadersSecurityCheckerInternal.RuleIdPublicKeyPinsDeprecated,
						headerName,
						multipleHeaderValuesRaw,
					),
				}
			}
		case "X-AspNet-Version":
			if len(headerValues) != 0 {
				headerResults = []*sarif.Result{
					httpHeadersSecurityCheckerInternal.MakeExposureResult(
						httpHeadersSecurityCheckerInternal.RuleIdXAspNetVersionHeaderExposure,
						headerName,
						multipleHeaderValuesRaw,
					),
				}
			}
		case "X-AspNetMvc-Version":
			if len(headerValues) != 0 {
				headerResults = []*sarif.Result{
					httpHeadersSecurityCheckerInternal.MakeExposureResult(
						httpHeadersSecurityCheckerInternal.RuleIdXAspNetMvcVersionHeaderExposure,
						headerName,
						multipleHeaderValuesRaw,
					),
				}
			}
		}

		allResults = append(allResults, headerResults...)
	}

	// A rule whose severity is dynamic carries the LevelDynamic placeholder until
	// the analyzer that raised it decides a level. That placeholder is not a valid
	// SARIF level, so anything that reaches this point unresolved would put an
	// invalid value on the wire; fall back to a valid level rather than emit it.
	for _, result := range allResults {
		if result != nil && result.Level == httpHeadersSecurityCheckerInternal.LevelDynamic {
			result.Level = sarif.LevelWarning
		}
	}

	return &sarif.Run{
		Tool: &sarif.Tool{
			Driver: &sarif.ToolComponent{
				Name:           ToolName,
				InformationUri: ToolInformationUri,
				Rules:          buildRules(allResults),
			},
		},
		Results: allResults,
	}, nil
}

func buildRules(results []*sarif.Result) []*sarif.ReportingDescriptor {
	seen := map[string]bool{}
	var rules []*sarif.ReportingDescriptor
	for _, r := range results {
		if r == nil || r.RuleId == "" || seen[r.RuleId] {
			continue
		}
		seen[r.RuleId] = true
		rule := &sarif.ReportingDescriptor{Id: r.RuleId}
		if r.Message != nil && r.Message.Text != "" {
			rule.FullDescription = &sarif.MultiformatMessageString{Text: r.Message.Text}
		}
		rules = append(rules, rule)
	}
	return rules
}
