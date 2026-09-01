package rule_id

const (
	MultipleHeaderValuesRuleId = "multiple_header_values"
	// A syntax_error rule is not emitted yet; malformed headers are reported
	// by the per-header invalid_* rules instead.
	InformationExposureRuleId = "information_exposure"

	MissingXContentTypeOptions  = "missing_x_content_type_options"
	XContentTypeOptionsBadValue = "x_content_type_options_bad_value"

	XFrameOptionsObsolete = "x_frame_options_obsolete"
	XFrameOptionsBadValue = "x_frame_options_bad_value"

	ReferrerPolicyUnsafeUrl = "referrer_policy_unsafe_url"

	MissingCrossOriginOpenerPolicy    = "missing_cross_origin_opener_policy"
	CrossOriginOpenerPolicyUnsafeNone = "cross_origin_opener_policy_unsafe_none"
	CrossOriginOpenerPolicyBadValue   = "cross_origin_opener_policy_bad_value"

	MissingCrossOriginEmbedderPolicy    = "missing_cross_origin_embedder_policy"
	CrossOriginEmbedderPolicyUnsafeNone = "cross_origin_embedder_policy_unsafe_none"
	CrossOriginEmbedderPolicyBadValue   = "cross_origin_embedder_policy_bad_value"

	MissingCrossOriginResourcePolicy     = "missing_cross_origin_resource_policy"
	CrossOriginResourcePolicyBadValue    = "cross_origin_resource_policy_bad_value"
	CrossOriginResourcePolicyCrossOrigin = "cross_origin_resource_policy_cross_origin"

	FeaturePolicyObsolete    = "feature_policy_obsolete"
	MissingPermissionsPolicy = "missing_permissions_policy"

	MissingContentSecurityPolicy = "missing_content_security_policy"
	InvalidContentSecurityPolicy = "invalid_content_security_policy"

	ContentSecurityPolicyHttp                           = "content_security_policy_https_scheme"
	ContentSecurityPolicyWildcardHost                   = "content_security_policy_wildcard_host"
	ContentSecurityPolicyWildcardRegisteredDomainHost   = "content_security_policy_wildcard_registered_domain_host"
	ContentSecurityPolicyLoopbackHost                   = "content_security_policy_loopback_host"
	ContentSecurityPolicyDataSchemeInSensitiveDirective = "content_security_policy_data_scheme_in_sensitive_directive"
	ContentSecurityPolicyNoScheme                       = "content_security_policy_no_scheme"
	ContentSecurityPolicyUnsafeInline                   = "content_security_policy_unsafe_inline"
	ContentSecurityPolicyUnsafeEval                     = "content_security_policy_unsafe_eval"
	ContentSecurityPolicyUnsafeHashes                   = "content_security_policy_unsafe_hashes"
	ContentSecurityPolicyUnsafeAllowRedirects           = "content_security_policy_unsafe_allow_redirects"
	ContentSecurityPolicyWasmUnsafeEval                 = "content_security_policy_wasm_unsafe_eval"
	ContentSecurityPolicyMissingDefaultSrc              = "content_security_policy_missing_default_src"
	ContentSecurityPolicyMissingFrameAncestors          = "content_security_policy_missing_frame_ancestors"
	ContentSecurityPolicyMissingBaseUri                 = "content_security_policy_missing_base_uri"
	ContentSecurityPolicyMissingFormAction              = "content_security_policy_missing_form_action"
	ContentSecurityPolicyInsecureDefaultSrc             = "content_security_policy_insecure_default_src"
	ContentSecurityPolicyInsecureFrameSrc               = "content_security_policy_insecure_frame_src"
	ContentSecurityPolicyInsecureBaseUri                = "content_security_policy_insecure_base_uri"
	ContentSecurityPolicyInsecureFormAction             = "content_security_policy_insecure_form_action"
	ContentSecurityPolicyInsecureFrameAncestors         = "content_security_policy_insecure_frame_ancestors"
	ContentSecurityPolicyIneffectiveDirective           = "content_security_policy_ineffective_directive"
	ContentSecurityPolicyCdnScriptSource                = "content_security_policy_cdn_script_source"
	ContentSecurityPolicyMissingRequireSriForScript     = "content_security_policy_missing_require_sri_for_script"
	ContentSecurityPolicyMissingRequireSriForStyle      = "content_security_policy_missing_require_sri_for_style"

	MissingStrictTransportSecurity                  = "missing_strict_transport_security"
	InvalidStrictTransportSecurity                  = "invalid_strict_transport_security"
	StrictTransportSecurityMissingOrLowMaxAge       = "strict_transport_security_missing_or_low_max_age"
	StrictTransportSecurityMissingIncludeSubdomains = "strict_transport_security_missing_include_subdomains"
	StrictTransportSecurityMissingPreload           = "strict_transport_security_missing_preload"

	// An access_control_allow_origin_wildcard rule is not implemented yet.
)
