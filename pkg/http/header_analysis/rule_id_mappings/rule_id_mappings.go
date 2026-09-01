package rule_id_mappings

import (
	"github.com/altshiftab/altshift_web_security/pkg/http/header_analysis/rule_id"
)

const XContentTypeNoSniffDescription = "The X-Content-Type-Options header should be set to a value of \"nosniff\". This instructs user agents not to infer the content type of an HTTP response body, forcing them to trust the declared Content-Type."
const CrossOriginOpenerPolicyDescription = "The Cross-Origin-Opener-Policy header should be set to the value \"same-origin\". This isolates the browsing context exclusively to same-origin documents. Cross-origin documents are not loaded in the same browsing context, so attackers cannot access your global object if they were to open it in a popup. This protects against a set of cross-origin attacks dubbed XS-Leaks."
const CrossOriginEmbedderPolicyDescription = "The Cross-Origin-Embedder-Policy header should be set to either the value \"require-corp\" or \"credentialless\". With this header, cross-origin resources need to grant explicit access in order to be loaded. This feature exists to protect against advanced side-channel attacks in which an attacker that has gained control of a web page, e.g. via cross-site scripting (XSS), would be able to learn about a user's activity on other web pages."
const CrossOriginResourcePolicyDescription = "The Cross-Origin-Resource-Policy header should be set to the value \"same-origin\". This limits the origins that are allowed to load your resources. This feature exists to protect against advanced side-channel attacks in which an attacker-controlled external page would be able to read sensitive user-specific data from your resources."
const ContentSecurityPolicyFrameAncestorsDescription = "The Content-Security-Policy header should include a frame-ancestor directive, which limits the parent pages that may embed the current page. Using a restrictive value such as 'none', 'self' or one or more specific hosts protects users of the page against various types of click-jacking attacks and cross-site leaks (XS-Leaks)."
const ContentSecurityPolicyBaseUriDescription = "The Content-Security-Policy header should include a base-uri directive, which limits the URLs that can be used in <base> elements of the current page. Using a restrictive value such as 'none', 'self', or one or more specific hosts protects users of the page against attacks where the attacker can arrange to add or manipulate a <base> element to load malicious external content."
const ContentSecurityPolicyFormActionDescription = "The Content-Security-Policy header should include a form-action directive, which limits the URLs that can be used as the target of form submission. Using a restrictive value such as 'none', 'self', or one or more specific hosts protects users of the page against cross-site request forgery (CSRF) attacks and data exfiltration if an attacker has managed to control the web page."
const ContentSecurityPolicyDefaultSrcDescription = "The \"default-src\" directive of the Content-Security-Policy functions as a fallback source when none more specific is defined. The directive should be set to either of the restrictive values 'self', 'none', or one or more specific hosts in order to serve as an effective, restrictive default, to protect against a variety of attacks associated with malicious external content, including cross-site scripting (XSS), cross-site request forgery (CSRF), cross-site leaks (XS-Leaks), and data exfiltration."

// Severity is the qualitative severity a rule carries. It is mapped onto a SARIF
// level for emission; see internal.SeverityToLevel.
type Severity string

const (
	SeverityHigh   Severity = "high"
	SeverityMedium Severity = "medium"
	SeverityLow    Severity = "low"
	SeverityInfo   Severity = "info"

	// SeverityDynamic marks a rule whose severity is not fixed by the rule
	// itself but decided per finding at analysis time - a CSP finding's
	// severity depends on the directive it was found on, for instance. The
	// analyzer is expected to overwrite the level before emitting the result.
	SeverityDynamic Severity = dynamicSentinel
)

// dynamicSentinel marks an entry in any of the lookup tables below as resolved
// at analysis time rather than fixed by the rule.
const dynamicSentinel = "DYNAMIC"

// RuleIdToSeverity, RuleIdToTitle and RuleIdToDescription are parallel lookup
// tables keyed by rule id. They are kept separate rather than merged into one
// table of structs so that each stays readable as a single body of curated
// text.
//
//nolint:dupl // deliberately parallel static tables; the shared key set is the point, not copied logic.
var RuleIdToSeverity = map[string]Severity{
	rule_id.MissingXContentTypeOptions:  SeverityHigh,
	rule_id.XContentTypeOptionsBadValue: SeverityHigh,

	rule_id.XFrameOptionsObsolete: SeverityInfo,
	rule_id.XFrameOptionsBadValue: SeverityMedium,

	rule_id.ReferrerPolicyUnsafeUrl: SeverityMedium,

	rule_id.MissingCrossOriginOpenerPolicy:    SeverityLow,
	rule_id.CrossOriginOpenerPolicyUnsafeNone: SeverityLow,
	rule_id.CrossOriginOpenerPolicyBadValue:   SeverityLow,

	rule_id.MissingCrossOriginEmbedderPolicy:    SeverityLow,
	rule_id.CrossOriginEmbedderPolicyUnsafeNone: SeverityLow,
	rule_id.CrossOriginEmbedderPolicyBadValue:   SeverityLow,

	rule_id.MissingCrossOriginResourcePolicy:     SeverityLow,
	rule_id.CrossOriginResourcePolicyBadValue:    SeverityLow,
	rule_id.CrossOriginResourcePolicyCrossOrigin: SeverityLow,

	rule_id.FeaturePolicyObsolete:    SeverityInfo,
	rule_id.MissingPermissionsPolicy: SeverityLow,

	rule_id.MissingContentSecurityPolicy: SeverityHigh,
	rule_id.InvalidContentSecurityPolicy: SeverityHigh,

	rule_id.ContentSecurityPolicyHttp:                           SeverityMedium,
	rule_id.ContentSecurityPolicyWildcardHost:                   SeverityDynamic,
	rule_id.ContentSecurityPolicyWildcardRegisteredDomainHost:   SeverityDynamic,
	rule_id.ContentSecurityPolicyLoopbackHost:                   SeverityDynamic,
	rule_id.ContentSecurityPolicyDataSchemeInSensitiveDirective: SeverityHigh,
	rule_id.ContentSecurityPolicyNoScheme:                       SeverityMedium,
	rule_id.ContentSecurityPolicyUnsafeInline:                   SeverityDynamic,
	rule_id.ContentSecurityPolicyUnsafeEval:                     SeverityDynamic,
	rule_id.ContentSecurityPolicyUnsafeHashes:                   SeverityDynamic,
	//rule_id.ContentSecurityPolicyUnsafeAllowRedirects:           "",
	rule_id.ContentSecurityPolicyWasmUnsafeEval:             SeverityDynamic,
	rule_id.ContentSecurityPolicyMissingDefaultSrc:          SeverityHigh,
	rule_id.ContentSecurityPolicyMissingFrameAncestors:      SeverityMedium,
	rule_id.ContentSecurityPolicyMissingBaseUri:             SeverityMedium,
	rule_id.ContentSecurityPolicyMissingFormAction:          SeverityMedium,
	rule_id.ContentSecurityPolicyInsecureDefaultSrc:         SeverityHigh,
	rule_id.ContentSecurityPolicyInsecureFrameSrc:           SeverityMedium,
	rule_id.ContentSecurityPolicyInsecureBaseUri:            SeverityMedium,
	rule_id.ContentSecurityPolicyInsecureFormAction:         SeverityMedium,
	rule_id.ContentSecurityPolicyInsecureFrameAncestors:     SeverityMedium,
	rule_id.ContentSecurityPolicyIneffectiveDirective:       SeverityInfo,
	rule_id.ContentSecurityPolicyCdnScriptSource:            SeverityHigh,
	rule_id.ContentSecurityPolicyMissingRequireSriForScript: SeverityInfo,
	rule_id.ContentSecurityPolicyMissingRequireSriForStyle:  SeverityInfo,

	rule_id.MissingStrictTransportSecurity:                  SeverityHigh,
	rule_id.InvalidStrictTransportSecurity:                  SeverityHigh,
	rule_id.StrictTransportSecurityMissingOrLowMaxAge:       SeverityMedium,
	rule_id.StrictTransportSecurityMissingIncludeSubdomains: SeverityLow,
	rule_id.StrictTransportSecurityMissingPreload:           SeverityInfo,
}

//nolint:dupl // see the note on RuleIdToSeverity.
var RuleIdToTitle = map[string]string{
	rule_id.MissingXContentTypeOptions:  "The X-Content-Type-Options header is missing",
	rule_id.XContentTypeOptionsBadValue: "The X-Content-Type-Options header is not set to \"nosniff\"",

	rule_id.XFrameOptionsObsolete: "The obsolete X-Frame-Options header is being used",
	rule_id.XFrameOptionsBadValue: "The X-Frame-Options header has an invalid value",

	rule_id.ReferrerPolicyUnsafeUrl: "The Referrer-Policy header is set to \"unsafe-url\"",

	rule_id.MissingCrossOriginOpenerPolicy:    "The Cross-Origin-Opener-Policy header is missing",
	rule_id.CrossOriginOpenerPolicyUnsafeNone: "The Cross-Origin-Opener-Policy header is set to the unsafe value \"unsafe-none\"",
	rule_id.CrossOriginOpenerPolicyBadValue:   "The Cross-Origin-Opener-Policy header is not set to the recommended value \"same-origin\"",

	rule_id.MissingCrossOriginEmbedderPolicy:    "The Cross-Origin-Embedder-Policy header is missing",
	rule_id.CrossOriginEmbedderPolicyUnsafeNone: "The Cross-Origin-Embedder-Policy header is set to the unsafe value \"unsafe-none\"",
	rule_id.CrossOriginEmbedderPolicyBadValue:   "The Cross-Origin-Embedder-Policy header is not set to either of the accepted values \"require-corp\" or \"credentialless\"",

	rule_id.MissingCrossOriginResourcePolicy:     "The Cross-Origin-Resource-Policy header is missing",
	rule_id.CrossOriginResourcePolicyBadValue:    "The Cross-Origin-Resource-Policy header is not set to the recommended value \"same-site\"",
	rule_id.CrossOriginResourcePolicyCrossOrigin: "The Cross-Origin-Resource-Policy header is set to the unsafe value \"cross-origin\"",

	rule_id.FeaturePolicyObsolete:    "The obsolete Feature-Policy header is being used",
	rule_id.MissingPermissionsPolicy: "The Permissions-Policy header is missing",

	rule_id.MissingContentSecurityPolicy: "The Content-Security-Policy header is missing",
	rule_id.InvalidContentSecurityPolicy: "The Content-Security-Policy header value is not syntactically correct",

	rule_id.ContentSecurityPolicyHttp:                           dynamicSentinel,
	rule_id.ContentSecurityPolicyWildcardHost:                   dynamicSentinel,
	rule_id.ContentSecurityPolicyWildcardRegisteredDomainHost:   dynamicSentinel,
	rule_id.ContentSecurityPolicyLoopbackHost:                   dynamicSentinel,
	rule_id.ContentSecurityPolicyDataSchemeInSensitiveDirective: dynamicSentinel,
	rule_id.ContentSecurityPolicyNoScheme:                       dynamicSentinel,
	rule_id.ContentSecurityPolicyUnsafeInline:                   dynamicSentinel,
	rule_id.ContentSecurityPolicyUnsafeEval:                     dynamicSentinel,
	rule_id.ContentSecurityPolicyUnsafeHashes:                   dynamicSentinel,
	//rule_id.ContentSecurityPolicyUnsafeAllowRedirects:           "",
	rule_id.ContentSecurityPolicyWasmUnsafeEval:             dynamicSentinel,
	rule_id.ContentSecurityPolicyMissingDefaultSrc:          "The Content-Security-Policy header is missing the default-src directive",
	rule_id.ContentSecurityPolicyMissingFrameAncestors:      "The Content-Security-Policy header is missing the frame-ancestors directive",
	rule_id.ContentSecurityPolicyMissingBaseUri:             "The Content-Security-Policy header is missing the base-uri directive",
	rule_id.ContentSecurityPolicyMissingFormAction:          "The Content-Security-Policy header is missing the form-action directive",
	rule_id.ContentSecurityPolicyInsecureDefaultSrc:         "The default-src directive of the Content-Security-Policy header is not set to a safe value",
	rule_id.ContentSecurityPolicyInsecureFrameSrc:           "The frame-src directive of the Content-Security-Policy header is not set to a safe value",
	rule_id.ContentSecurityPolicyInsecureBaseUri:            "The base-uri directive of the Content-Security-Policy header is not set to a safe value",
	rule_id.ContentSecurityPolicyInsecureFormAction:         "The form-action directive of the Content-Security-Policy header is not set to a safe value",
	rule_id.ContentSecurityPolicyInsecureFrameAncestors:     "The frame-ancestors directive of the Content-Security-Policy header is not set to a safe value",
	rule_id.ContentSecurityPolicyIneffectiveDirective:       dynamicSentinel,
	rule_id.ContentSecurityPolicyCdnScriptSource:            dynamicSentinel,
	rule_id.ContentSecurityPolicyMissingRequireSriForScript: "The Content-Security-Policy header is missing the require-sri-for directive with the script resource type set.",
	rule_id.ContentSecurityPolicyMissingRequireSriForStyle:  "The Content-Security-Policy header is missing the require-sri-for directive with the style resource type set.",

	rule_id.MissingStrictTransportSecurity:                  "The Strict-Transport-Security header is missing",
	rule_id.InvalidStrictTransportSecurity:                  "The Strict-Transport-Security header value is not syntactically correct",
	rule_id.StrictTransportSecurityMissingOrLowMaxAge:       "The \"max-age\" directive of the Strict-Transport-Security header does not have a sufficiently long expiry time",
	rule_id.StrictTransportSecurityMissingIncludeSubdomains: "The Strict-Transport-Security header is missing the \"includeSubdomains\" directive",
	rule_id.StrictTransportSecurityMissingPreload:           "The Strict-Transport-Security header is missing the \"preload\" directive",
}

var RuleIdToDescription = map[string]string{
	rule_id.MultipleHeaderValuesRuleId: "Multiple headers with the same field name were observed. This is most likely unintentional and could affect the enforcement of the header.",
	//rule_id.SyntaxErrorRuleId: "The value of the header is not syntactically correct, rendering its use ().",

	rule_id.MissingXContentTypeOptions:  XContentTypeNoSniffDescription,
	rule_id.XContentTypeOptionsBadValue: XContentTypeNoSniffDescription,

	rule_id.XFrameOptionsObsolete: "The X-Frame-Options header is obsoleted in favor of the frame-ancestors directive of the Content-Security-Policy HTTP header.",
	rule_id.XFrameOptionsBadValue: "The X-Frame-Options header is set to an invalid value. Accepted values are \"DENY\" and \"SAMEORIGIN\", case insensitive.",

	rule_id.ReferrerPolicyUnsafeUrl: "The \"unsafe-url\" directive instructs web browsers to send the full URL in its referrer information. This is considered unsafe as the query string could contain sensitive information.",

	rule_id.MissingCrossOriginOpenerPolicy:    CrossOriginOpenerPolicyDescription,
	rule_id.CrossOriginOpenerPolicyUnsafeNone: CrossOriginOpenerPolicyDescription,
	rule_id.CrossOriginOpenerPolicyBadValue:   CrossOriginOpenerPolicyDescription,

	rule_id.MissingCrossOriginEmbedderPolicy:    CrossOriginEmbedderPolicyDescription,
	rule_id.CrossOriginEmbedderPolicyUnsafeNone: CrossOriginEmbedderPolicyDescription,
	rule_id.CrossOriginEmbedderPolicyBadValue:   CrossOriginEmbedderPolicyDescription,

	rule_id.MissingCrossOriginResourcePolicy:     CrossOriginResourcePolicyDescription,
	rule_id.CrossOriginResourcePolicyBadValue:    CrossOriginResourcePolicyDescription,
	rule_id.CrossOriginResourcePolicyCrossOrigin: CrossOriginResourcePolicyDescription,

	rule_id.FeaturePolicyObsolete:    "The Feature-Policy header is obsoleted in favor of the Permissions-Policy HTTP header",
	rule_id.MissingPermissionsPolicy: "The Permissions-Policy header limits a web page's access to certain features, with the option to disable them altogether. If an attacker manages to control a web page, e.g. via cross-site scripting (XSS), this header can ensure that potentially sensitive features such as video recording, audio recording, and geolocation remain inaccessible.",

	rule_id.MissingContentSecurityPolicy: "The Content-Security-Policy header specifies various directives that control how external resources may be loaded and by what means interaction with external hosts may occur. A restrictive policy protects against cross-site scripting (XSS), cross-site request forgery (CSRF), cross-site leaks (XS-Leaks), click-jacking, and data exfiltration.",
	rule_id.InvalidContentSecurityPolicy: "The Content-Security-Policy header value is not syntactically correct, rendering it ineffective.",

	rule_id.ContentSecurityPolicyHttp:                           dynamicSentinel,
	rule_id.ContentSecurityPolicyWildcardHost:                   dynamicSentinel,
	rule_id.ContentSecurityPolicyWildcardRegisteredDomainHost:   dynamicSentinel,
	rule_id.ContentSecurityPolicyLoopbackHost:                   dynamicSentinel,
	rule_id.ContentSecurityPolicyDataSchemeInSensitiveDirective: dynamicSentinel,
	rule_id.ContentSecurityPolicyNoScheme:                       dynamicSentinel,
	rule_id.ContentSecurityPolicyUnsafeInline:                   dynamicSentinel,
	rule_id.ContentSecurityPolicyUnsafeEval:                     dynamicSentinel,
	rule_id.ContentSecurityPolicyUnsafeHashes:                   dynamicSentinel,
	//rule_id.ContentSecurityPolicyUnsafeAllowRedirects:           "",
	rule_id.ContentSecurityPolicyWasmUnsafeEval:             dynamicSentinel,
	rule_id.ContentSecurityPolicyMissingDefaultSrc:          ContentSecurityPolicyDefaultSrcDescription,
	rule_id.ContentSecurityPolicyMissingFrameAncestors:      ContentSecurityPolicyFrameAncestorsDescription,
	rule_id.ContentSecurityPolicyMissingBaseUri:             ContentSecurityPolicyBaseUriDescription,
	rule_id.ContentSecurityPolicyMissingFormAction:          ContentSecurityPolicyFormActionDescription,
	rule_id.ContentSecurityPolicyInsecureDefaultSrc:         ContentSecurityPolicyDefaultSrcDescription,
	rule_id.ContentSecurityPolicyInsecureFrameSrc:           "The \"frame-src\" directive of the Content-Security-Policy header limits from what sources iframes may be loaded. It should be set to either of the restrictive values 'self', 'none', or one or more specific hosts in order to prevent unauthorized, potentially malicious, content from being framed on web pages.",
	rule_id.ContentSecurityPolicyInsecureBaseUri:            ContentSecurityPolicyBaseUriDescription,
	rule_id.ContentSecurityPolicyInsecureFormAction:         ContentSecurityPolicyFormActionDescription,
	rule_id.ContentSecurityPolicyInsecureFrameAncestors:     ContentSecurityPolicyFrameAncestorsDescription,
	rule_id.ContentSecurityPolicyIneffectiveDirective:       dynamicSentinel,
	rule_id.ContentSecurityPolicyCdnScriptSource:            dynamicSentinel,
	rule_id.ContentSecurityPolicyMissingRequireSriForScript: "The Content-Security-Policy header should include a require-sri-for directive with a script resource type, which asserts that all loaded script resources need to be integrity checked. Note: this directive is not yet widely supported, hence a severity of \"info\".",
	rule_id.ContentSecurityPolicyMissingRequireSriForStyle:  "The Content-Security-Policy header should include a require-sri-for directive with a style resource type, which asserts that all loaded style resources need to be integrity checked. Note: this directive is not yet widely supported, hence a severity of \"info\".",

	rule_id.MissingStrictTransportSecurity:                  "The Strict-Transport-Security header instructs web browsers to load web pages of the site only over an encrypted channel, via HTTPS. This provides effective protection against man-in-the-middle attacks such as eavesdropping and content alteration.",
	rule_id.InvalidStrictTransportSecurity:                  "The Strict-Transport-Security header value is not syntactically correct, rendering it ineffective",
	rule_id.StrictTransportSecurityMissingOrLowMaxAge:       "The \"max-age\" directive of the Strict-Transport-Security header should have an expiry time of at least one year (31536000).",
	rule_id.StrictTransportSecurityMissingIncludeSubdomains: "The \"includeSubdomains\" directive of the Strict-Transport-Security header is missing. It should be included in order to also protect all subdomains.",
	rule_id.StrictTransportSecurityMissingPreload:           "The \"preload\" directive of the Strict-Transport-Security header is missing. Including it allows the site to be added to the HSTS preload list maintained by browser vendors, which guarantees that visitors are protected on the first connection rather than only after the first response is observed.",
}
