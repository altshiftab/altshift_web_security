package content_security_policy

import (
	"errors"
	"fmt"
	"net"
	"strings"

	httpHeadersSecurityCheckerInternal "github.com/altshiftab/altshift_web_security/pkg/http/header_analysis/analysis/internal"
	"github.com/altshiftab/altshift_web_security/pkg/http/header_analysis/rule_id"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	contentSecurityPolicyTypes "github.com/altshiftab/utils_go/pkg/http/types/content_security_policy"
	"github.com/altshiftab/utils_go/pkg/net/types/domain_parts"
	"github.com/altshiftab/utils_go/pkg/sarif"
)

var (
	ErrUnexpectedSourceType = errors.New("unexpected source type")
)

const (
	directiveDefaultSrc = "default-src"
	directiveScriptSrc  = "script-src"
	directiveStyleSrc   = "style-src"

	directiveBaseUri        = "base-uri"
	directiveChildSrc       = "child-src"
	directiveFormAction     = "form-action"
	directiveFrameAncestors = "frame-ancestors"
	directiveFrameSrc       = "frame-src"
)

// noEffectSuffix is appended when a keyword is used on a directive it has no
// bearing on: the keyword is inert there, so naming it is a mistake in itself.
const noEffectSuffix = " Though it has no effect with the directive with which it is associated, indicating its use there is an error."

var cdnFullDomainsSet = map[string]bool{
	"cdnjs.cloudflare.com": true,
}

var cdnRegisteredDomainsSet = map[string]bool{
	"googleapis.com": true,
	"gstatic.com":    true,
	"unpkg.com":      true,
	"jsdelivr.net":   true,
}

// Properties naming what in the policy a result is about, so that a consumer can show the
// directive and source beside the finding rather than recover them from the message prose.
const (
	// PropertyDirective is the name of the directive the result is about. A result about a missing
	// directive names the one that is missing.
	PropertyDirective = "directive"
	// PropertyDirectiveValue is that directive's value as the policy states it, absent where the
	// directive is missing or has no value.
	PropertyDirectiveValue = "directiveValue"
	// PropertySource is the one source of the directive that caused the result, where one did.
	PropertySource = "source"
)

// setProperty sets a property on each result that does not already carry it, leaving one set
// closer to the finding as it is.
func setProperty(results []*sarif.Result, name string, value string) {
	if value == "" {
		return
	}

	for _, result := range results {
		if result == nil {
			continue
		}
		if result.Properties == nil {
			result.Properties = sarif.PropertyBag{}
		}
		if _, ok := result.Properties[name]; !ok {
			result.Properties[name] = value
		}
	}
}

// setDirective says which directive the results are about; directive is nil where it is missing.
func setDirective(results []*sarif.Result, name string, directive contentSecurityPolicyTypes.DirectiveI) {
	setProperty(results, PropertyDirective, name)
	if directive != nil {
		setProperty(results, PropertyDirectiveValue, directive.GetRawValue())
	}
}

func getDirectiveNameUntrustedSourceLevel(directiveName string) sarif.Level {
	switch directiveName {
	case "base-uri", "child-src", "connect-src", directiveDefaultSrc, "frame-ancestors", "frame-src", "script-src", "script-src-attr", "script-src-elem", "worker-src":
		return sarif.LevelError
	case "form-action", "style-src", "style-src-attr", "style-src-elem":
		return sarif.LevelWarning
	default:
		return sarif.LevelNote
	}
}

func makeHttpResult(directiveName string, source contentSecurityPolicyTypes.SourceI) *sarif.Result {
	result := httpHeadersSecurityCheckerInternal.MakeRuleIdResult(rule_id.ContentSecurityPolicyHttp)
	result.Message = &sarif.Message{
		Text: fmt.Sprintf(
			"The %s source of the %s directive uses an http scheme. Using the http scheme is unsafe as it permits content to be loaded over an unencrypted channel, which enables man-in-the-middle attacks such as eavesdropping and content alteration.",
			source.String(),
			directiveName,
		),
	}
	return result
}

func makeWildcardResult(directiveName string, source contentSecurityPolicyTypes.SourceI) *sarif.Result {
	result := httpHeadersSecurityCheckerInternal.MakeRuleIdResult(rule_id.ContentSecurityPolicyWildcardHost)
	result.Message = &sarif.Message{
		Text: fmt.Sprintf(
			"The %s source of the %s directive effectively uses a wildcard host source. Using a wildcard in place of the host is unsafe as it permits content to be loaded from any external host.",
			source.String(),
			directiveName,
		),
	}
	result.Level = getDirectiveNameUntrustedSourceLevel(directiveName)
	return result
}

func checkSources(directiveName string, sources []contentSecurityPolicyTypes.SourceI) (bool, []*sarif.Result, error) {
	if len(sources) == 0 {
		return false, nil, nil
	}

	results := make([]*sarif.Result, 0, len(sources))

	strict := true

	for _, source := range sources {
		sourceStart := len(results)

		switch typedSource := source.(type) {
		case *contentSecurityPolicyTypes.NoneSource:
			// The CSP grammar only accepts 'none' as the entire source list, so a
			// 'none'-alongside-others combination is never produced by the parser.
		case *contentSecurityPolicyTypes.SchemeSource:
			strict = false
			switch strings.ToLower(typedSource.Scheme) {
			case "http":
				results = append(results, makeHttpResult(directiveName, source))
				results = append(results, makeWildcardResult(directiveName, source))
			case "https":
				results = append(results, makeWildcardResult(directiveName, source))
			// TODO: Should more schemes be added?
			case "data":
				if directiveName == directiveDefaultSrc || directiveName == directiveScriptSrc || directiveName == "object-src" {
					result := httpHeadersSecurityCheckerInternal.MakeRuleIdResult(rule_id.ContentSecurityPolicyDataSchemeInSensitiveDirective)
					result.Message = &sarif.Message{
						Text: fmt.Sprintf("Use of the data: source in the %s directive is considered not safe as the directive is especially sensitive and should be restricted to specific sources, in order to protect against cross-site scripting (XSS).", directiveName),
					}
					results = append(results, result)
				}
			}
		case *contentSecurityPolicyTypes.HostSource:
			strict = false
			if typedSource.Host == "*" {
				results = append(results, makeWildcardResult(directiveName, source))
			}

			ip := net.ParseIP(typedSource.Host)
			if (ip != nil && ip.IsLoopback()) || typedSource.Host == "localhost" {
				result := httpHeadersSecurityCheckerInternal.MakeRuleIdResult(rule_id.ContentSecurityPolicyLoopbackHost)
				result.Message = &sarif.Message{
					Text: fmt.Sprintf(
						"The %s source of the %s directive uses a loopback source. Using a loopback source is unwarranted and unsafe as it could enable content injection attacks in a compromised system.",
						source.String(),
						directiveName,
					),
				}
				result.Level = getDirectiveNameUntrustedSourceLevel(directiveName)
				strict = false
				results = append(results, result)
			}

			scheme := typedSource.Scheme

			switch scheme {
			case "http":
				strict = false
				results = append(results, makeHttpResult(directiveName, source))
			case "":
				result := httpHeadersSecurityCheckerInternal.MakeRuleIdResult(rule_id.ContentSecurityPolicyNoScheme)
				result.Message = &sarif.Message{
					Text: fmt.Sprintf(
						"The %s source of the %s directive uses a host source without a scheme. Specifying a host source without a scheme is unsafe as it permits content to be loaded with protocols that do not support encryption, which enables man-in-the-middle attacks such as eavesdropping and content alteration.",
						source.String(),
						directiveName,
					),
				}
				strict = false
				results = append(results, result)
			}

			if host := typedSource.Host; host != "" {
				// TODO: This branch is currently unreachable: domain_parts.New calls
				// publicsuffix.EffectiveTLDPlusOne, which errors on any host containing
				// "*", so dp is nil for inputs like "*.com" or "*.co.uk". Switch to a
				// wildcard-aware variant (domain_parts_config with AllowWildcards) so
				// the check can actually fire.
				if dp := domain_parts.New(host); dp != nil {
					if dp.RegisteredDomain == "*" {
						result := httpHeadersSecurityCheckerInternal.MakeRuleIdResult(rule_id.ContentSecurityPolicyWildcardRegisteredDomainHost)
						result.Message = &sarif.Message{
							Text: fmt.Sprintf(
								"The %s source of the %s directive effectively uses a wildcard host source. Using a wildcard in place of the registered domain of a host is unsafe as it permits content to be loaded from any external host with a specific effective top-level domain.",
								source.String(),
								directiveName,
							),
						}
						result.Level = getDirectiveNameUntrustedSourceLevel(directiveName)
						results = append(results, result)
					} else {
						switch directiveName {
						case directiveDefaultSrc, "script-src", "script-src-attr", "script-src-elem", "worker-src":
							var cdnDomain string
							if _, ok := cdnFullDomainsSet[host]; ok {
								cdnDomain = host
							} else if _, ok := cdnRegisteredDomainsSet[dp.RegisteredDomain]; ok {
								cdnDomain = dp.RegisteredDomain
							}
							if cdnDomain != "" {
								result := httpHeadersSecurityCheckerInternal.MakeRuleIdResult(rule_id.ContentSecurityPolicyCdnScriptSource)
								result.Message = &sarif.Message{
									Text: fmt.Sprintf(
										"The %s directive, which controls code execution, uses a content-delivery network (CDN) host source with the domain %s. Permitting code to be loaded and executed from CDNs effectively renders a directive ineffective as CDNs are hosting user-provided content, which an attacker could arrange to be malicious to achieve cross-site scripting (XSS) etc.",
										directiveName,
										cdnDomain,
									),
								}
								results = append(results, result)
							}
						}
					}
				}
			}
		case *contentSecurityPolicyTypes.KeywordSource:
			keyword := strings.ToLower(typedSource.Keyword)

			switch keyword {
			case "self", "strict-dynamic":
				// preserve strict
			default:
				strict = false
			}

			description := fmt.Sprintf(
				"A source of the %s directive uses an %s keyword.",
				directiveName,
				keyword,
			)
			switch keyword {
			case "unsafe-inline":
				result := httpHeadersSecurityCheckerInternal.MakeRuleIdResult(rule_id.ContentSecurityPolicyUnsafeInline)

				switch directiveName {
				case directiveScriptSrc, directiveDefaultSrc:
					description += " In the context of script-src, 'unsafe-inline' enables cross-site scripting (XSS) attacks as overly-permissive means of executing JavaScript are permitted, including inline <script> elements, inline event handlers, and javascript: URLs."
					result.Level = sarif.LevelError
				case directiveStyleSrc:
					description += " In the context of style-src, 'unsafe-inline' can enable various types of social engineering and exfiltration attacks as overly-permissive means of defining document styles are permitted, including inline <style> elements and inline style attributes."
					result.Level = sarif.LevelWarning
				default:
					description += noEffectSuffix
					result.Level = sarif.LevelNone
				}
				result.Message = &sarif.Message{Text: description}
				results = append(results, result)
			case "unsafe-eval":
				result := httpHeadersSecurityCheckerInternal.MakeRuleIdResult(rule_id.ContentSecurityPolicyUnsafeEval)

				switch directiveName {
				case directiveScriptSrc, directiveDefaultSrc:
					description += " The 'unsafe-eval' keyword source enables cross-site scripting (XSS) attacks as dynamic means of executing JavaScript are permitted, including via the eval function, Function objects, the setTimeout function, the setInterval function, and WebAssembly functions."
					result.Level = sarif.LevelError
				default:
					description += noEffectSuffix
					result.Level = sarif.LevelNone
				}
				result.Message = &sarif.Message{Text: description}
				results = append(results, result)
			case "unsafe-hashes":
				result := httpHeadersSecurityCheckerInternal.MakeRuleIdResult(rule_id.ContentSecurityPolicyUnsafeHashes)

				switch directiveName {
				case directiveScriptSrc, directiveDefaultSrc:
					description += " The 'unsafe-hashes' keyword source is a stricter version of the unsafe-inline keyword source, limiting the permitted inline means of executing JavaScript to event handlers, that are allowed via content hashes. Any inline means of executing JavaScript is nevertheless considered unsafe and can enable cross-site scripting (XSS) attacks."
					result.Level = sarif.LevelNote
				default:
					description += noEffectSuffix
					result.Level = sarif.LevelNone
				}
				result.Message = &sarif.Message{Text: description}
				results = append(results, result)

			// NOTE: This keyword does not seem to be described by any authoritative source I can find... Skipping for now.
			case "unsafe-allow-redirects":
			case "wasm-unsafe-eval":
				result := httpHeadersSecurityCheckerInternal.MakeRuleIdResult(rule_id.ContentSecurityPolicyWasmUnsafeEval)

				switch directiveName {
				case directiveScriptSrc, directiveDefaultSrc:
					description += " The wasm-unsafe-eval keyword source is a stricter version of the unsafe-eval keyword source, limiting the permitted dynamic means of executing JavaScript to WebAssembly functions. Any dynamic means of executing JavaScript is nevertheless considered unsafe and can enable cross-site scripting (XSS) attacks."
					result.Level = sarif.LevelError
				default:
					description += noEffectSuffix
					result.Level = sarif.LevelNone
				}
				result.Message = &sarif.Message{Text: description}
				results = append(results, result)
			}
		case *contentSecurityPolicyTypes.NonceSource:
		case *contentSecurityPolicyTypes.HashSource:
		default:
			return false, nil, altshiftErrors.NewWithTrace(fmt.Errorf("%w: %s", ErrUnexpectedSourceType, source))
		}

		setProperty(results[sourceStart:], PropertySource, source.String())
	}

	return strict, results, nil
}

func Analyze(headerValue string) ([]*sarif.Result, error) {
	if headerValue == "" {
		return nil, nil
	}

	data := []byte(headerValue)
	contentSecurityPolicy, err := contentSecurityPolicyTypes.Parse(data)
	if err != nil {
		if altshiftErrors.IsAny(err, altshiftErrors.ErrSyntaxError, altshiftErrors.ErrSemanticError) {
			return []*sarif.Result{
				httpHeadersSecurityCheckerInternal.MakeRuleIdResult(rule_id.InvalidContentSecurityPolicy),
			}, nil
		}

		return nil, altshiftErrors.New(fmt.Errorf("parse content security policy: %w", err), data)
	}

	var allResults []*sarif.Result

	var defaultSrcDefined bool
	var strictDefaultSource bool

	var childSrcDefined bool
	var strictChildSrc bool

	var frameSrcDefined bool
	var strictFrameSrc bool

	var baseUriDefined bool
	var strictBaseUri bool

	var formActionDefined bool
	var strictFormAction bool

	var frameAncestorsDefined bool
	var strictFrameAncestors bool

	for _, directive := range contentSecurityPolicy.Directives {
		directiveName := directive.GetName()

		var results []*sarif.Result
		var strict bool
		var err error

		switch typedDirective := directive.(type) {
		case *contentSecurityPolicyTypes.ChildSrcDirective:
			strict, results, err = checkSources(directiveName, typedDirective.Sources)
			childSrcDefined = true
			strictChildSrc = strict
		case *contentSecurityPolicyTypes.ConnectSrcDirective:
			_, results, err = checkSources(directiveName, typedDirective.Sources)
		case *contentSecurityPolicyTypes.FontSrcDirective:
			_, results, err = checkSources(directiveName, typedDirective.Sources)
		case *contentSecurityPolicyTypes.FrameSrcDirective:
			strict, results, err = checkSources(directiveName, typedDirective.Sources)
			frameSrcDefined = true
			strictFrameSrc = strict
		case *contentSecurityPolicyTypes.ImgSrcDirective:
			_, results, err = checkSources(directiveName, typedDirective.Sources)
		case *contentSecurityPolicyTypes.ManifestSrcDirective:
			_, results, err = checkSources(directiveName, typedDirective.Sources)
		case *contentSecurityPolicyTypes.MediaSrcDirective:
			_, results, err = checkSources(directiveName, typedDirective.Sources)
		case *contentSecurityPolicyTypes.ObjectSrcDirective:
			_, results, err = checkSources(directiveName, typedDirective.Sources)
		case *contentSecurityPolicyTypes.ScriptSrcAttrDirective:
			_, results, err = checkSources(directiveName, typedDirective.Sources)
		case *contentSecurityPolicyTypes.ScriptSrcDirective:
			_, results, err = checkSources(directiveName, typedDirective.Sources)
		case *contentSecurityPolicyTypes.ScriptSrcElemDirective:
			_, results, err = checkSources(directiveName, typedDirective.Sources)
		case *contentSecurityPolicyTypes.StyleSrcAttrDirective:
			_, results, err = checkSources(directiveName, typedDirective.Sources)
		case *contentSecurityPolicyTypes.StyleSrcDirective:
			_, results, err = checkSources(directiveName, typedDirective.Sources)
		case *contentSecurityPolicyTypes.StyleSrcElemDirective:
			_, results, err = checkSources(directiveName, typedDirective.Sources)
		case *contentSecurityPolicyTypes.WorkerSrcDirective:
			_, results, err = checkSources(directiveName, typedDirective.Sources)
		case *contentSecurityPolicyTypes.DefaultSrcDirective:
			strict, results, err = checkSources(directiveName, typedDirective.Sources)
			defaultSrcDefined = true
			strictDefaultSource = strict
		case *contentSecurityPolicyTypes.BaseUriDirective:
			strict, results, err = checkSources(directiveName, typedDirective.Sources)
			baseUriDefined = true
			strictBaseUri = strict
		case *contentSecurityPolicyTypes.FormActionDirective:
			strict, results, err = checkSources(directiveName, typedDirective.Sources)
			formActionDefined = true
			strictFormAction = strict
		case *contentSecurityPolicyTypes.SandboxDirective:
		case *contentSecurityPolicyTypes.WebrtcDirective:
		case *contentSecurityPolicyTypes.ReportUriDirective:
		case *contentSecurityPolicyTypes.ReportToDirective:
		case *contentSecurityPolicyTypes.RequireSriForDirective:
		case *contentSecurityPolicyTypes.FrameAncestorsDirective:
			strict, results, err = checkSources(directiveName, typedDirective.Sources)
			frameAncestorsDefined = true
			strictFrameAncestors = strict
		}

		if err != nil {
			return nil, altshiftErrors.New(fmt.Errorf("check sources: %w", err), directiveName)
		}

		setDirective(results, directiveName, directive)
		allResults = append(allResults, results...)
	}

	// The policy-wide results below are about a directive by name, one that is either missing or
	// not strict enough; the effective ones are unique by name, the duplicates being set aside as
	// ineffective.
	directivesByName := make(map[string]contentSecurityPolicyTypes.DirectiveI, len(contentSecurityPolicy.Directives))
	for _, directive := range contentSecurityPolicy.Directives {
		if directive != nil {
			directivesByName[directive.GetName()] = directive
		}
	}

	policyResult := func(ruleId string, directiveName string) *sarif.Result {
		result := httpHeadersSecurityCheckerInternal.MakeRuleIdResult(ruleId)
		setDirective([]*sarif.Result{result}, directiveName, directivesByName[directiveName])
		return result
	}

	if !defaultSrcDefined {
		result := policyResult(rule_id.ContentSecurityPolicyMissingDefaultSrc, directiveDefaultSrc)
		if result.Message != nil {
			result.Message.Text += " When no such directive is defined, the fallback is to allow any source."
		}
		allResults = append(allResults, result)
	} else if !strictDefaultSource {
		allResults = append(allResults, policyResult(rule_id.ContentSecurityPolicyInsecureDefaultSrc, directiveDefaultSrc))
	}

	if !baseUriDefined {
		allResults = append(allResults, policyResult(rule_id.ContentSecurityPolicyMissingBaseUri, directiveBaseUri))
	} else if !strictBaseUri {
		allResults = append(allResults, policyResult(rule_id.ContentSecurityPolicyInsecureBaseUri, directiveBaseUri))
	}

	if !formActionDefined {
		allResults = append(allResults, policyResult(rule_id.ContentSecurityPolicyMissingFormAction, directiveFormAction))
	} else if !strictFormAction {
		allResults = append(allResults, policyResult(rule_id.ContentSecurityPolicyInsecureFormAction, directiveFormAction))
	}

	if !frameAncestorsDefined {
		allResults = append(allResults, policyResult(rule_id.ContentSecurityPolicyMissingFrameAncestors, directiveFrameAncestors))
	} else if !strictFrameAncestors {
		allResults = append(allResults, policyResult(rule_id.ContentSecurityPolicyInsecureFrameAncestors, directiveFrameAncestors))
	}

	// Framing falls back from frame-src to child-src to default-src, and the result names whichever
	// of them governs; where none is defined, it is frame-src that is missing.
	if frameSrcDefined {
		if !strictFrameSrc {
			allResults = append(allResults, policyResult(rule_id.ContentSecurityPolicyInsecureFrameSrc, directiveFrameSrc))
		}
	} else {
		if childSrcDefined {
			if !strictChildSrc {
				allResults = append(allResults, policyResult(rule_id.ContentSecurityPolicyInsecureFrameSrc, directiveChildSrc))
			}
		} else if defaultSrcDefined {
			if !strictDefaultSource {
				allResults = append(allResults, policyResult(rule_id.ContentSecurityPolicyInsecureFrameSrc, directiveDefaultSrc))
			}
		} else {
			allResults = append(allResults, policyResult(rule_id.ContentSecurityPolicyInsecureFrameSrc, directiveFrameSrc))
		}
	}

	for _, ineffectiveDirective := range contentSecurityPolicy.IneffectiveDirectives {
		result := httpHeadersSecurityCheckerInternal.MakeRuleIdResult(rule_id.ContentSecurityPolicyIneffectiveDirective)
		result.Message = &sarif.Message{
			Text: fmt.Sprintf(
				"The directive %q is rendered ineffective as another directive with the same name was defined earlier.",
				ineffectiveDirective.String(),
			),
		}
		setDirective([]*sarif.Result{result}, ineffectiveDirective.GetName(), ineffectiveDirective)
		allResults = append(allResults, result)
	}

	return allResults, nil
}
