package analysis

import (
	"net/http"
	"slices"
	"testing"

	httpHeadersSecurityCheckerInternal "github.com/altshiftab/altshift_web_security/pkg/http/header_analysis/analysis/internal"
	"github.com/altshiftab/altshift_web_security/pkg/http/header_analysis/rule_id"
	"github.com/altshiftab/utils_go/pkg/sarif"
)

func TestAnalyzeHeaders_NilHeader(t *testing.T) {
	t.Parallel()

	got, err := AnalyzeHeaders(nil)
	if err != nil {
		t.Fatalf("AnalyzeHeaders(nil) err = %v", err)
	}
	if got != nil {
		t.Fatalf("AnalyzeHeaders(nil) = %v, want nil", got)
	}
}

func TestAnalyzeHeaders_EmptyHeader(t *testing.T) {
	t.Parallel()

	got, err := AnalyzeHeaders(http.Header{})
	if err != nil {
		t.Fatalf("AnalyzeHeaders({}) err = %v", err)
	}
	if got == nil {
		t.Fatalf("AnalyzeHeaders({}) = nil, want non-nil")
	}

	// Every "missing" rule for required headers should fire.
	wantIDs := []string{
		rule_id.MissingContentSecurityPolicy,
		rule_id.MissingCrossOriginEmbedderPolicy,
		rule_id.MissingCrossOriginOpenerPolicy,
		rule_id.MissingCrossOriginResourcePolicy,
		rule_id.MissingPermissionsPolicy,
		rule_id.MissingStrictTransportSecurity,
		rule_id.MissingXContentTypeOptions,
	}
	gotIDs := allResultIDs(got)
	if !slices.Equal(gotIDs, wantIDs) {
		t.Fatalf("missing-rule IDs = %v, want %v", gotIDs, wantIDs)
	}
}

func TestAnalyzeHeaders_DispatchPerHeader(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		header   http.Header
		mustHave []string
	}{
		{
			name:     "X-XSS-Protection emits obsoletion",
			header:   http.Header{"X-Xss-Protection": []string{"1; mode=block"}},
			mustHave: []string{httpHeadersSecurityCheckerInternal.RuleIdXXssProtectionObsolete},
		},
		{
			name:     "X-Frame-Options emits obsolete",
			header:   http.Header{"X-Frame-Options": []string{"SAMEORIGIN"}},
			mustHave: []string{rule_id.XFrameOptionsObsolete},
		},
		{
			name:     "Server emits exposure",
			header:   http.Header{"Server": []string{"nginx/1.24.0"}},
			mustHave: []string{httpHeadersSecurityCheckerInternal.RuleIdServerHeaderExposure},
		},
		{
			name:     "Feature-Policy emits obsolete",
			header:   http.Header{"Feature-Policy": []string{"camera 'none'"}},
			mustHave: []string{rule_id.FeaturePolicyObsolete},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := AnalyzeHeaders(tc.header)
			if err != nil {
				t.Fatalf("AnalyzeHeaders err = %v", err)
			}
			gotIDs := allResultIDs(got)
			for _, want := range tc.mustHave {
				if !slices.Contains(gotIDs, want) {
					t.Fatalf("result IDs = %v, want to include %q", gotIDs, want)
				}
			}
		})
	}
}

func TestAnalyzeHeaders_MultipleHeaders(t *testing.T) {
	t.Parallel()

	header := http.Header{
		"Strict-Transport-Security": []string{
			"max-age=31536000",
			"max-age=63072000; includeSubDomains",
		},
	}

	got, err := AnalyzeHeaders(header)
	if err != nil {
		t.Fatalf("AnalyzeHeaders err = %v", err)
	}
	if got == nil {
		t.Fatalf("AnalyzeHeaders returned nil run")
	}

	gotIDs := allResultIDs(got)
	if !slices.Contains(gotIDs, rule_id.MultipleHeaderValuesRuleId) {
		t.Fatalf("STS multi-header IDs = %v, want to include %q", gotIDs, rule_id.MultipleHeaderValuesRuleId)
	}
}

func TestAnalyzeHeaders_ExposureAndDeprecation(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		header   http.Header
		mustHave []string
	}{
		{
			name:     "X-Powered-By exposure",
			header:   http.Header{"X-Powered-By": []string{"Express"}},
			mustHave: []string{httpHeadersSecurityCheckerInternal.RuleIdXPoweredByHeaderExposure},
		},
		{
			name:     "X-AspNet-Version exposure",
			header:   http.Header{"X-Aspnet-Version": []string{"4.0.30319"}},
			mustHave: []string{httpHeadersSecurityCheckerInternal.RuleIdXAspNetVersionHeaderExposure},
		},
		{
			name:     "X-AspNetMvc-Version exposure",
			header:   http.Header{"X-Aspnetmvc-Version": []string{"5.2"}},
			mustHave: []string{httpHeadersSecurityCheckerInternal.RuleIdXAspNetMvcVersionHeaderExposure},
		},
		{
			name:     "Expect-CT deprecation",
			header:   http.Header{"Expect-Ct": []string{"max-age=86400"}},
			mustHave: []string{httpHeadersSecurityCheckerInternal.RuleIdExpectCtDeprecated},
		},
		{
			name:     "Public-Key-Pins deprecation",
			header:   http.Header{"Public-Key-Pins": []string{"pin-sha256=\"abc\"; max-age=5184000"}},
			mustHave: []string{httpHeadersSecurityCheckerInternal.RuleIdPublicKeyPinsDeprecated},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := AnalyzeHeaders(tc.header)
			if err != nil {
				t.Fatalf("AnalyzeHeaders err = %v", err)
			}
			gotIDs := allResultIDs(got)
			for _, want := range tc.mustHave {
				if !slices.Contains(gotIDs, want) {
					t.Fatalf("result IDs = %v, want to include %q", gotIDs, want)
				}
			}
		})
	}
}

func TestAnalyzeHeaders_MultipleHeaderValues(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		header http.Header
	}{
		{
			name:   "X-Frame-Options",
			header: http.Header{"X-Frame-Options": []string{"DENY", "SAMEORIGIN"}},
		},
		{
			name:   "X-Content-Type-Options",
			header: http.Header{"X-Content-Type-Options": []string{"nosniff", "nosniff"}},
		},
		{
			name:   "Referrer-Policy",
			header: http.Header{"Referrer-Policy": []string{"no-referrer", "strict-origin"}},
		},
		{
			name:   "Cross-Origin-Opener-Policy",
			header: http.Header{"Cross-Origin-Opener-Policy": []string{"same-origin", "same-origin"}},
		},
		{
			name:   "Cross-Origin-Embedder-Policy",
			header: http.Header{"Cross-Origin-Embedder-Policy": []string{"require-corp", "credentialless"}},
		},
		{
			name:   "Cross-Origin-Resource-Policy",
			header: http.Header{"Cross-Origin-Resource-Policy": []string{"same-origin", "same-site"}},
		},
		{
			name:   "Permissions-Policy",
			header: http.Header{"Permissions-Policy": []string{"camera=()", "geolocation=()"}},
		},
		{
			name: "Content-Security-Policy",
			header: http.Header{"Content-Security-Policy": []string{
				"default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'self'",
				"default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'self'",
			}},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := AnalyzeHeaders(tc.header)
			if err != nil {
				t.Fatalf("AnalyzeHeaders err = %v", err)
			}
			gotIDs := allResultIDs(got)
			if !slices.Contains(gotIDs, rule_id.MultipleHeaderValuesRuleId) {
				t.Fatalf("result IDs = %v, want to include %q", gotIDs, rule_id.MultipleHeaderValuesRuleId)
			}
		})
	}
}

func TestAnalyzeHeaders_NoBodyDowngradesMissingDocumentHeaders(t *testing.T) {
	t.Parallel()

	// Headers from the example: a 301 redirect with no Content-Length / Content-Type /
	// Transfer-Encoding. Missing CSP/COOP/COEP/Permissions-Policy must be downgraded
	// to LevelNone; Missing-CORP / Missing-X-CTO / Missing-STS keep their configured
	// levels (and here are not even missing).
	header := http.Header{
		"Cross-Origin-Resource-Policy": []string{"same-origin"},
		"Strict-Transport-Security":    []string{"max-age=31536000; includeSubDomains"},
		"X-Content-Type-Options":       []string{"nosniff"},
	}

	got, err := AnalyzeHeaders(header)
	if err != nil {
		t.Fatalf("AnalyzeHeaders err = %v", err)
	}

	wantDowngraded := map[string]bool{
		rule_id.MissingContentSecurityPolicy:     true,
		rule_id.MissingCrossOriginOpenerPolicy:   true,
		rule_id.MissingCrossOriginEmbedderPolicy: true,
		rule_id.MissingPermissionsPolicy:         true,
	}

	if got == nil {
		t.Fatal("expected a run, got nil")
	}

	for _, r := range got.Results {
		if wantDowngraded[r.RuleId] {
			if r.Level != sarif.LevelNone {
				t.Fatalf("rule %q level = %q, want %q (no body)", r.RuleId, r.Level, sarif.LevelNone)
			}
			delete(wantDowngraded, r.RuleId)
		}
	}
	if len(wantDowngraded) != 0 {
		t.Fatalf("expected downgraded results not emitted: %v", wantDowngraded)
	}
}

func TestAnalyzeHeaders_BodyKeepsConfiguredLevel(t *testing.T) {
	t.Parallel()

	// Content-Type signals a body — Missing-CSP must keep its configured level
	// (error), not be downgraded.
	header := http.Header{
		"Content-Type": []string{"text/html; charset=utf-8"},
	}

	got, err := AnalyzeHeaders(header)
	if err != nil {
		t.Fatalf("AnalyzeHeaders err = %v", err)
	}

	if got == nil {
		t.Fatal("expected a run, got nil")
	}

	for _, r := range got.Results {
		if r.RuleId == rule_id.MissingContentSecurityPolicy {
			if r.Level == sarif.LevelNone {
				t.Fatalf("Missing-CSP level = %q with body present — should retain configured level", r.Level)
			}
			return
		}
	}
	t.Fatalf("Missing-CSP result not emitted")
}

func TestResponseHasBody(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		header http.Header
		want   bool
	}{
		{name: "empty header", header: http.Header{}, want: false},
		{name: "only Location (redirect)", header: http.Header{"Location": []string{"https://example.com/"}}, want: false},
		{name: "Content-Length 0", header: http.Header{"Content-Length": []string{"0"}}, want: false},
		{name: "Content-Length 0 trumps Content-Type", header: http.Header{"Content-Length": []string{"0"}, "Content-Type": []string{"text/html"}}, want: false},
		{name: "non-zero Content-Length", header: http.Header{"Content-Length": []string{"42"}}, want: true},
		{name: "Transfer-Encoding chunked", header: http.Header{"Transfer-Encoding": []string{"chunked"}}, want: true},
		{name: "Content-Type only", header: http.Header{"Content-Type": []string{"text/html"}}, want: true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := responseHasBody(tc.header); got != tc.want {
				t.Fatalf("responseHasBody(%v) = %v, want %v", tc.header, got, tc.want)
			}
		})
	}
}

func TestAnalyzeHeaders_StableResultOrder(t *testing.T) {
	t.Parallel()

	// Same input run twice should produce the same result ordering.
	header := http.Header{
		"X-Frame-Options":              []string{"SAMEORIGIN"},
		"Strict-Transport-Security":    []string{"max-age=31536000; includeSubDomains; preload"},
		"Content-Security-Policy":      []string{"default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'self'"},
		"Cross-Origin-Opener-Policy":   []string{"same-origin"},
		"Cross-Origin-Embedder-Policy": []string{"require-corp"},
		"Cross-Origin-Resource-Policy": []string{"same-origin"},
		"X-Content-Type-Options":       []string{"nosniff"},
		"Permissions-Policy":           []string{"camera=()"},
	}

	first, err := AnalyzeHeaders(header)
	if err != nil {
		t.Fatalf("first AnalyzeHeaders err = %v", err)
	}

	for i := range 5 {
		next, err := AnalyzeHeaders(header)
		if err != nil {
			t.Fatalf("AnalyzeHeaders err on iteration %d: %v", i, err)
		}
		if !slices.Equal(allResultIDs(first), allResultIDs(next)) {
			t.Fatalf("result ordering changed on iteration %d", i)
		}
	}
}

// allResultIDs returns the rule ids from a run's results, sorted, for stable comparison.
func allResultIDs(run *sarif.Run) []string {
	if run == nil || len(run.Results) == 0 {
		return nil
	}
	ids := make([]string, 0, len(run.Results))
	for _, r := range run.Results {
		ids = append(ids, r.RuleId)
	}
	slices.Sort(ids)
	return ids
}
