package content_security_policy

import (
	"slices"
	"testing"

	"github.com/altshiftab/altshift_web_security/pkg/http/header_analysis/rule_id"
	"github.com/altshiftab/utils_go/pkg/sarif"
)

// strictBoilerplate keeps the four "core" directive-level findings silent so
// per-source tests below don't have to deal with them.
const strictBoilerplate = "base-uri 'self'; form-action 'self'; frame-ancestors 'self'"

func TestAnalyze_EmptyAndInvalid(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		input   string
		wantIDs []string
	}{
		{name: "empty", input: "", wantIDs: nil},
		{name: "syntax error", input: "this-is-not-a-policy@@@", wantIDs: []string{rule_id.InvalidContentSecurityPolicy}},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertResults(t, tc.input, tc.wantIDs)
		})
	}
}

func TestAnalyze_MissingDirectives(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		input   string
		wantIDs []string
	}{
		{
			name:  "only default-src — base-uri/form-action/frame-ancestors missing",
			input: "default-src 'self'",
			wantIDs: []string{
				rule_id.ContentSecurityPolicyMissingBaseUri,
				rule_id.ContentSecurityPolicyMissingFormAction,
				rule_id.ContentSecurityPolicyMissingFrameAncestors,
			},
		},
		{
			name:  "no default-src — falls through to multiple findings",
			input: "base-uri 'self'; form-action 'self'; frame-ancestors 'self'",
			wantIDs: []string{
				rule_id.ContentSecurityPolicyInsecureFrameSrc,
				rule_id.ContentSecurityPolicyMissingDefaultSrc,
			},
		},
		{
			name:    "fully defined strict policy — no problems",
			input:   "default-src 'self'; " + strictBoilerplate,
			wantIDs: nil,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertResults(t, tc.input, tc.wantIDs)
		})
	}
}

// Verifies the (3) strict-tracking fix.
func TestAnalyze_StrictTracking(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		input   string
		wantIDs []string
	}{
		{
			name:    "default-src 'self' is strict",
			input:   "default-src 'self'; " + strictBoilerplate,
			wantIDs: nil,
		},
		{
			name:    "nonce + strict-dynamic preserves strictness",
			input:   "default-src 'nonce-AbCd' 'strict-dynamic'; " + strictBoilerplate,
			wantIDs: nil,
		},
		{
			name:    "sha256 hash preserves strictness",
			input:   "default-src 'sha256-AbCdEf+/='; " + strictBoilerplate,
			wantIDs: nil,
		},
		{
			name:  "external host in default-src breaks strictness",
			input: "default-src 'self' https://cdn.example.com; " + strictBoilerplate,
			wantIDs: []string{
				rule_id.ContentSecurityPolicyInsecureDefaultSrc,
				rule_id.ContentSecurityPolicyInsecureFrameSrc,
			},
		},
		{
			// `*` parses as a HostSource with no scheme — both findings are expected.
			name:  "wildcard host breaks strictness and emits wildcard + no-scheme",
			input: "default-src *; " + strictBoilerplate,
			wantIDs: []string{
				rule_id.ContentSecurityPolicyInsecureDefaultSrc,
				rule_id.ContentSecurityPolicyInsecureFrameSrc,
				rule_id.ContentSecurityPolicyNoScheme,
				rule_id.ContentSecurityPolicyWildcardHost,
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertResults(t, tc.input, tc.wantIDs)
		})
	}
}

func TestAnalyze_PerSource(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		input   string
		wantIDs []string
	}{
		{
			name:  "unsafe-inline in script-src",
			input: "default-src 'self'; script-src 'self' 'unsafe-inline'; " + strictBoilerplate,
			wantIDs: []string{
				rule_id.ContentSecurityPolicyUnsafeInline,
			},
		},
		{
			name:  "unsafe-eval in script-src",
			input: "default-src 'self'; script-src 'self' 'unsafe-eval'; " + strictBoilerplate,
			wantIDs: []string{
				rule_id.ContentSecurityPolicyUnsafeEval,
			},
		},
		{
			name:  "wasm-unsafe-eval in script-src",
			input: "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; " + strictBoilerplate,
			wantIDs: []string{
				rule_id.ContentSecurityPolicyWasmUnsafeEval,
			},
		},
		{
			name:  "unsafe-hashes in script-src",
			input: "default-src 'self'; script-src 'self' 'unsafe-hashes'; " + strictBoilerplate,
			wantIDs: []string{
				rule_id.ContentSecurityPolicyUnsafeHashes,
			},
		},
		{
			name:  "data: in script-src",
			input: "default-src 'self'; script-src 'self' data:; " + strictBoilerplate,
			wantIDs: []string{
				rule_id.ContentSecurityPolicyDataSchemeInSensitiveDirective,
			},
		},
		{
			name:  "http scheme in default-src",
			input: "default-src 'self' http://example.com; " + strictBoilerplate,
			wantIDs: []string{
				rule_id.ContentSecurityPolicyHttp,
				rule_id.ContentSecurityPolicyInsecureDefaultSrc,
				rule_id.ContentSecurityPolicyInsecureFrameSrc,
			},
		},
		{
			name:  "loopback host",
			input: "default-src 'self' http://localhost; " + strictBoilerplate,
			wantIDs: []string{
				rule_id.ContentSecurityPolicyHttp,
				rule_id.ContentSecurityPolicyInsecureDefaultSrc,
				rule_id.ContentSecurityPolicyInsecureFrameSrc,
				rule_id.ContentSecurityPolicyLoopbackHost,
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertResults(t, tc.input, tc.wantIDs)
		})
	}
}

// Verifies the (12) refactor: wildcard registered domain and CDN script source
// are emitted from inside checkSources rather than a second pass.
func TestAnalyze_HostBasedFindings(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		input   string
		wantIDs []string
	}{
		{
			name:  "CDN host in script-src",
			input: "default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com; " + strictBoilerplate,
			wantIDs: []string{
				rule_id.ContentSecurityPolicyCdnScriptSource,
			},
		},
		{
			name:  "CDN registered domain in script-src",
			input: "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; " + strictBoilerplate,
			wantIDs: []string{
				rule_id.ContentSecurityPolicyCdnScriptSource,
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertResults(t, tc.input, tc.wantIDs)
		})
	}
}

func TestAnalyze_KeywordInNonScriptDirective(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		input   string
		wantIDs []string
	}{
		{
			// Style-src branch of unsafe-inline (medium severity).
			name:    "unsafe-inline in style-src",
			input:   "default-src 'self'; style-src 'self' 'unsafe-inline'; " + strictBoilerplate,
			wantIDs: []string{rule_id.ContentSecurityPolicyUnsafeInline},
		},
		{
			// Else arm: keyword has no effect in this directive type.
			name:    "unsafe-inline in img-src",
			input:   "default-src 'self'; img-src 'self' 'unsafe-inline'; " + strictBoilerplate,
			wantIDs: []string{rule_id.ContentSecurityPolicyUnsafeInline},
		},
		{
			name:    "unsafe-eval in connect-src",
			input:   "default-src 'self'; connect-src 'self' 'unsafe-eval'; " + strictBoilerplate,
			wantIDs: []string{rule_id.ContentSecurityPolicyUnsafeEval},
		},
		{
			name:    "unsafe-hashes in style-src",
			input:   "default-src 'self'; style-src 'self' 'unsafe-hashes'; " + strictBoilerplate,
			wantIDs: []string{rule_id.ContentSecurityPolicyUnsafeHashes},
		},
		{
			name:    "wasm-unsafe-eval in img-src",
			input:   "default-src 'self'; img-src 'self' 'wasm-unsafe-eval'; " + strictBoilerplate,
			wantIDs: []string{rule_id.ContentSecurityPolicyWasmUnsafeEval},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertResults(t, tc.input, tc.wantIDs)
		})
	}
}

func TestAnalyze_LoopbackIPLiteral(t *testing.T) {
	t.Parallel()

	// 127.0.0.1 hits the net.ParseIP/IsLoopback branch, not the literal "localhost" branch.
	input := "default-src 'self' http://127.0.0.1; " + strictBoilerplate
	assertResults(t, input, []string{
		rule_id.ContentSecurityPolicyHttp,
		rule_id.ContentSecurityPolicyInsecureDefaultSrc,
		rule_id.ContentSecurityPolicyInsecureFrameSrc,
		rule_id.ContentSecurityPolicyLoopbackHost,
	})
}

func TestAnalyze_DirectiveSeverityClassification(t *testing.T) {
	t.Parallel()

	// form-action is in the "medium" severity directive set; img-src is in "low".
	// Just exercising the severity-lookup branches.
	cases := []struct {
		name    string
		input   string
		wantIDs []string
	}{
		{
			name:    "wildcard host in form-action — medium directive",
			input:   "default-src 'self'; form-action *; base-uri 'self'; frame-ancestors 'self'",
			wantIDs: []string{rule_id.ContentSecurityPolicyInsecureFormAction, rule_id.ContentSecurityPolicyNoScheme, rule_id.ContentSecurityPolicyWildcardHost},
		},
		{
			name:    "wildcard host in img-src — low directive",
			input:   "default-src 'self'; img-src *; " + strictBoilerplate,
			wantIDs: []string{rule_id.ContentSecurityPolicyNoScheme, rule_id.ContentSecurityPolicyWildcardHost},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertResults(t, tc.input, tc.wantIDs)
		})
	}
}

func TestAnalyze_FrameSrcCascade(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		input   string
		wantIDs []string
	}{
		{
			// frame-src defined and strict.
			name:    "explicit strict frame-src",
			input:   "default-src 'self'; frame-src 'self'; " + strictBoilerplate,
			wantIDs: nil,
		},
		{
			// frame-src defined and non-strict.
			name:  "explicit insecure frame-src",
			input: "default-src 'self'; frame-src 'self' https://cdn.example.com; " + strictBoilerplate,
			wantIDs: []string{
				rule_id.ContentSecurityPolicyInsecureFrameSrc,
			},
		},
		{
			// frame-src missing, child-src defined and strict.
			name:    "child-src strict fallback",
			input:   "default-src 'self'; child-src 'self'; " + strictBoilerplate,
			wantIDs: nil,
		},
		{
			// frame-src missing, child-src defined and non-strict.
			name:  "child-src insecure fallback",
			input: "default-src 'self'; child-src 'self' https://cdn.example.com; " + strictBoilerplate,
			wantIDs: []string{
				rule_id.ContentSecurityPolicyInsecureFrameSrc,
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertResults(t, tc.input, tc.wantIDs)
		})
	}
}

// TestAnalyze_AllDirectiveTypes exercises every directive case in the type-switch,
// including the no-op directive types (sandbox, webrtc, report-uri/-to, require-sri-for).
func TestAnalyze_AllDirectiveTypes(t *testing.T) {
	t.Parallel()

	input := "default-src 'self'; " +
		"child-src 'self'; " +
		"connect-src 'self'; " +
		"font-src 'self'; " +
		"frame-src 'self'; " +
		"img-src 'self'; " +
		"manifest-src 'self'; " +
		"media-src 'self'; " +
		"object-src 'self'; " +
		"script-src 'self'; " +
		"script-src-attr 'self'; " +
		"script-src-elem 'self'; " +
		"style-src 'self'; " +
		"style-src-attr 'self'; " +
		"style-src-elem 'self'; " +
		"worker-src 'self'; " +
		"sandbox; " +
		"webrtc 'allow'; " +
		"report-uri /csp-reports; " +
		"report-to default; " +
		"require-sri-for script style; " +
		strictBoilerplate

	assertResults(t, input, nil)
}

func TestAnalyze_HttpSchemeSource(t *testing.T) {
	t.Parallel()

	// `http:` (SchemeSource, not HostSource) emits both http + wildcard problems.
	input := "default-src 'self'; img-src http:; " + strictBoilerplate
	assertResults(t, input, []string{
		rule_id.ContentSecurityPolicyHttp,
		rule_id.ContentSecurityPolicyWildcardHost,
	})
}

func TestAnalyze_InsecureBaseUriAndFrameAncestors(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		input   string
		wantIDs []string
	}{
		{
			name:  "insecure base-uri",
			input: "default-src 'self'; base-uri *; form-action 'self'; frame-ancestors 'self'",
			wantIDs: []string{
				rule_id.ContentSecurityPolicyInsecureBaseUri,
				rule_id.ContentSecurityPolicyNoScheme,
				rule_id.ContentSecurityPolicyWildcardHost,
			},
		},
		{
			name:  "insecure frame-ancestors",
			input: "default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors *",
			wantIDs: []string{
				rule_id.ContentSecurityPolicyInsecureFrameAncestors,
				rule_id.ContentSecurityPolicyNoScheme,
				rule_id.ContentSecurityPolicyWildcardHost,
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertResults(t, tc.input, tc.wantIDs)
		})
	}
}

func TestAnalyze_HttpsSchemeSource(t *testing.T) {
	t.Parallel()

	// `https:` as a SchemeSource emits the wildcard problem (any host over HTTPS).
	input := "default-src 'self'; img-src https:; " + strictBoilerplate
	assertResults(t, input, []string{rule_id.ContentSecurityPolicyWildcardHost})
}

func TestAnalyze_LocalhostLiteralHost(t *testing.T) {
	t.Parallel()

	// "localhost" host literal hits the loopback branch via the string equality, not net.ParseIP.
	input := "default-src 'self' http://localhost; " + strictBoilerplate
	assertResults(t, input, []string{
		rule_id.ContentSecurityPolicyHttp,
		rule_id.ContentSecurityPolicyInsecureDefaultSrc,
		rule_id.ContentSecurityPolicyInsecureFrameSrc,
		rule_id.ContentSecurityPolicyLoopbackHost,
	})
}

func TestAnalyze_IneffectiveDirective(t *testing.T) {
	t.Parallel()

	// The second default-src is shadowed by the first per the CSP spec.
	input := "default-src 'self'; default-src 'unsafe-inline'; " + strictBoilerplate
	assertResults(t, input, []string{
		rule_id.ContentSecurityPolicyIneffectiveDirective,
	})
}

func assertResults(t *testing.T, input string, wantIDs []string) {
	t.Helper()
	got, err := Analyze(input)
	if err != nil {
		t.Fatalf("Analyze(%q) err = %v", input, err)
	}
	gotIDs := resultIDs(got)
	if !slices.Equal(gotIDs, wantIDs) {
		t.Fatalf("Analyze(%q) IDs = %v, want %v", input, gotIDs, wantIDs)
	}
}

func resultIDs(results []*sarif.Result) []string {
	if len(results) == 0 {
		return nil
	}
	ids := make([]string, 0, len(results))
	for _, r := range results {
		ids = append(ids, r.RuleId)
	}
	slices.Sort(ids)
	return ids
}
