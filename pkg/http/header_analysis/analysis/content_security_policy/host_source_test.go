package content_security_policy

import (
	"slices"
	"testing"

	"github.com/altshiftab/altshift_web_security/pkg/http/header_analysis/rule_id"
	"github.com/altshiftab/utils_go/pkg/sarif"
)

// sourceRuleIds are the rules that judge a host source by what it lets through, of which a source earns at most one.
var sourceRuleIds = []string{
	rule_id.ContentSecurityPolicyUserContentScriptSource,
	rule_id.ContentSecurityPolicyJsonpScriptSource,
	rule_id.ContentSecurityPolicyScriptGadgetSource,
	rule_id.ContentSecurityPolicyCdnScriptSource,
	rule_id.ContentSecurityPolicyWildcardRegisteredDomainHost,
}

func TestAnalyze_ScriptSourceBypasses(t *testing.T) {
	t.Parallel()

	const (
		userContent = rule_id.ContentSecurityPolicyUserContentScriptSource
		jsonp       = rule_id.ContentSecurityPolicyJsonpScriptSource
		gadget      = rule_id.ContentSecurityPolicyScriptGadgetSource
		cdn         = rule_id.ContentSecurityPolicyCdnScriptSource
		wildcard    = rule_id.ContentSecurityPolicyWildcardRegisteredDomainHost
	)

	testCases := []struct {
		name      string
		directive string
		sources   string
		// ruleId is the one source rule expected, empty for none.
		ruleId string
		level  sarif.Level
	}{
		// Sources the CDN rule missed.
		{name: "ajax.googleapis.com", sources: "https://ajax.googleapis.com", ruleId: jsonp, level: sarif.LevelError},
		{name: "storage.googleapis.com", sources: "https://storage.googleapis.com", ruleId: userContent, level: sarif.LevelError},
		{name: "*.googleusercontent.com", sources: "https://*.googleusercontent.com", ruleId: jsonp, level: sarif.LevelError},
		{name: "raw.githubusercontent.com", sources: "https://raw.githubusercontent.com", ruleId: userContent, level: sarif.LevelError},
		{name: "*.github.io", sources: "https://*.github.io", ruleId: userContent, level: sarif.LevelError},
		{name: "*.cloudfront.net", sources: "https://*.cloudfront.net", ruleId: userContent, level: sarif.LevelError},
		{name: "*.s3.amazonaws.com", sources: "https://*.s3.amazonaws.com", ruleId: userContent, level: sarif.LevelError},
		{name: "*.appspot.com", sources: "https://*.appspot.com", ruleId: userContent, level: sarif.LevelError},
		{name: "*.web.app", sources: "https://*.web.app", ruleId: userContent, level: sarif.LevelError},
		{name: "*.firebaseapp.com", sources: "https://*.firebaseapp.com", ruleId: userContent, level: sarif.LevelError},
		{name: "*.herokuapp.com", sources: "https://*.herokuapp.com", ruleId: userContent, level: sarif.LevelError},
		{name: "*.netlify.app", sources: "https://*.netlify.app", ruleId: userContent, level: sarif.LevelError},
		{name: "*.vercel.app", sources: "https://*.vercel.app", ruleId: userContent, level: sarif.LevelError},
		{name: "*.pages.dev", sources: "https://*.pages.dev", ruleId: userContent, level: sarif.LevelError},
		{name: "*.workers.dev", sources: "https://*.workers.dev", ruleId: userContent, level: sarif.LevelError},
		{name: "*.blob.core.windows.net", sources: "https://*.blob.core.windows.net", ruleId: userContent, level: sarif.LevelError},
		{name: "accounts.google.com", sources: "https://accounts.google.com", ruleId: jsonp, level: sarif.LevelError},
		{name: "www.google.com", sources: "https://www.google.com", ruleId: jsonp, level: sarif.LevelError},

		// Hosts the CDN rule caught, each now explained by the rule that fits it.
		{name: "cdnjs, a gadget host", sources: "https://cdnjs.cloudflare.com", ruleId: gadget, level: sarif.LevelError},
		{name: "jsDelivr, serving npm", sources: "https://cdn.jsdelivr.net", ruleId: userContent, level: sarif.LevelError},
		{name: "a wildcard over jsDelivr", sources: "https://*.jsdelivr.net", ruleId: userContent, level: sarif.LevelError},
		{name: "unpkg, serving npm", sources: "https://unpkg.com", ruleId: userContent, level: sarif.LevelError},
		{name: "www.gstatic.com, a gadget host", sources: "https://www.gstatic.com", ruleId: gadget, level: sarif.LevelError},

		// A path confines a source, as CSP Evaluator matches its lists.
		{name: "a path away from the JSONP endpoint", sources: "https://www.google.com/recaptcha/", ruleId: ""},
		{name: "a directory holding the JSONP endpoint", sources: "https://www.google.com/tools/feedback/", ruleId: jsonp, level: sarif.LevelError},
		{name: "the JSONP endpoint itself", sources: "https://www.google.com/tools/feedback/escalation-options", ruleId: jsonp, level: sarif.LevelError},
		{name: "a directory named like the JSONP endpoint", sources: "https://www.google.com/tools/feedback/escalation-options/", ruleId: ""},
		{name: "a file beside the JSONP endpoint", sources: "https://www.google.com/tools/feedback/other", ruleId: ""},
		{name: "a gadget's exact file", sources: "https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.8.2/angular.min.js", ruleId: gadget, level: sarif.LevelError},
		{name: "a directory a gadget pattern reaches into", sources: "https://unpkg.com/angular@1.8.2/", ruleId: gadget, level: sarif.LevelError},
		{name: "a directory no gadget pattern reaches", sources: "https://ajax.googleapis.com/ajax/libs/jquery/", ruleId: ""},
		{name: "a library that needs the page's code to be a gadget", sources: "https://code.jquery.com", ruleId: ""},
		{name: "where csp-toolkit says anyone publishes", sources: "https://cdn.statically.io/gh/", ruleId: userContent, level: sarif.LevelError},
		{name: "one npm package on jsDelivr", sources: "https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/", ruleId: userContent, level: sarif.LevelWarning},
		{name: "one repository on raw.githubusercontent.com", sources: "https://raw.githubusercontent.com/example/repository/", ruleId: userContent, level: sarif.LevelWarning},

		// One publisher's site on a platform, rather than the platform.
		{name: "one site on netlify.app", sources: "https://example.netlify.app", ruleId: userContent, level: sarif.LevelWarning},
		{name: "one distribution on cloudfront.net", sources: "https://d111111abcdef8.cloudfront.net", ruleId: userContent, level: sarif.LevelWarning},
		{name: "a wildcard under one site", sources: "https://*.example.github.io", ruleId: userContent, level: sarif.LevelWarning},
		{name: "a platform's shared endpoint", sources: "https://s3.amazonaws.com", ruleId: userContent, level: sarif.LevelError},
		{name: "a regional shared endpoint", sources: "https://s3.eu-west-1.amazonaws.com", ruleId: userContent, level: sarif.LevelError},
		{name: "a wildcard over a shared endpoint's buckets", sources: "https://*.storage.googleapis.com", ruleId: userContent, level: sarif.LevelError},
		{name: "a wildcard over a shared endpoint", sources: "https://*.amazonaws.com", ruleId: userContent, level: sarif.LevelError},
		{name: "one bucket by its subdomain", sources: "https://example-bucket.storage.googleapis.com", ruleId: userContent, level: sarif.LevelWarning},
		{name: "a platform's own host", sources: "https://github.io", ruleId: ""},
		{name: "another platform's own host", sources: "https://cloudfront.net", ruleId: ""},
		{name: "a service of a platform's operator", sources: "https://fonts.googleapis.com", ruleId: ""},
		{name: "a wildcard does not cover the listed host at its base", sources: "https://*.pastebin.com", ruleId: ""},
		{name: "one bucket on a platform's shared endpoint", sources: "https://s3.amazonaws.com/example-bucket/", ruleId: userContent, level: sarif.LevelWarning},
		{name: "a name a wildcard rule makes a suffix", sources: "https://ec2-192-0-2-1.compute-1.amazonaws.com", ruleId: userContent, level: sarif.LevelWarning},
		{name: "a wildcard over a wildcard rule", sources: "https://*.compute.amazonaws.com", ruleId: userContent, level: sarif.LevelError},
		{name: "upper case and a trailing dot", sources: "https://EXAMPLE.GitHub.IO.", ruleId: userContent, level: sarif.LevelWarning},

		// Wildcards spanning registered domains.
		{name: "*.com", sources: "https://*.com", ruleId: wildcard, level: sarif.LevelError},
		{name: "*.co.uk", sources: "https://*.co.uk", ruleId: wildcard, level: sarif.LevelError},
		{name: "*.ck, itself a wildcard rule", sources: "https://*.ck", ruleId: wildcard, level: sarif.LevelError},
		{name: "*.com in img-src", directive: "img-src", sources: "https://*.com", ruleId: wildcard, level: sarif.LevelNote},
		{name: "*.github.io in img-src", directive: "img-src", sources: "https://*.github.io", ruleId: wildcard, level: sarif.LevelNote},
		{name: "*.com in style-src", directive: "style-src", sources: "https://*.com", ruleId: wildcard, level: sarif.LevelWarning},
		{name: "a wildcard under a registered domain", sources: "https://*.example.com", ruleId: ""},
		{name: "a wildcard under a name no one registers", sources: "https://*.localhost", ruleId: ""},

		// What 'unsafe-eval' changes.
		{name: "an endpoint needing eval, without it", sources: "https://www.googletagmanager.com", ruleId: ""},
		{name: "an endpoint needing eval, with it", sources: "'unsafe-eval' https://www.googletagmanager.com", ruleId: jsonp, level: sarif.LevelError},

		// The directives that decide where script comes from, and the ones that do not.
		{name: "script-src-elem", directive: "script-src-elem", sources: "https://www.google.com", ruleId: jsonp, level: sarif.LevelError},
		{name: "worker-src", directive: "worker-src", sources: "https://*.github.io", ruleId: userContent, level: sarif.LevelError},
		{name: "img-src", directive: "img-src", sources: "https://www.google.com", ruleId: ""},
		{name: "connect-src", directive: "connect-src", sources: "https://raw.githubusercontent.com", ruleId: ""},
		{name: "style-src", directive: "style-src", sources: "https://example.netlify.app", ruleId: ""},

		// Host findings are not set aside for a nonce and 'strict-dynamic', as no host finding is.
		{name: "beside a nonce and 'strict-dynamic'", sources: "'nonce-AbCd' 'strict-dynamic' https://www.google.com", ruleId: jsonp, level: sarif.LevelError},

		// The lists name hosts on their default ports.
		{name: "another port", sources: "https://www.google.com:8443", ruleId: ""},
		{name: "the default port", sources: "https://www.google.com:443", ruleId: jsonp, level: sarif.LevelError},
		{name: "any port", sources: "https://www.google.com:*", ruleId: jsonp, level: sarif.LevelError},
		{name: "a wildcard over a platform on another port", sources: "https://*.github.io:8443", ruleId: wildcard, level: sarif.LevelError},

		// What the CDN rule is left with.
		{name: "a CDN host no list knows", sources: "https://data.jsdelivr.net", ruleId: cdn, level: sarif.LevelError},

		{name: "an ordinary host", sources: "https://example.com", ruleId: ""},
		{name: "an address", sources: "https://192.0.2.1", ruleId: ""},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			directive := testCase.directive
			if directive == "" {
				directive = directiveScriptSrc
			}
			input := "default-src 'self'; " + directive + " 'self' " + testCase.sources + "; " + strictBoilerplate

			results, err := Analyze(input)
			if err != nil {
				t.Fatalf("%s: Analyze(%q) err = %v", testCase.name, input, err)
			}

			var found []*sarif.Result
			for _, result := range results {
				if slices.Contains(sourceRuleIds, result.RuleId) {
					found = append(found, result)
				}
			}

			if testCase.ruleId == "" {
				if len(found) != 0 {
					t.Fatalf("%s: Analyze(%q) source results = %v, want none", testCase.name, input, resultIDs(found))
				}
				return
			}

			if len(found) != 1 || found[0].RuleId != testCase.ruleId {
				t.Fatalf("%s: Analyze(%q) source results = %v, want [%s]", testCase.name, input, resultIDs(found), testCase.ruleId)
			}
			if found[0].Level != testCase.level {
				t.Errorf("%s: level = %q, want %q", testCase.name, found[0].Level, testCase.level)
			}
		})
	}
}

// A whole policy around such a source keeps the findings it had and adds the one, and script-src decides whether
// eval is allowed, falling back to default-src.
func TestAnalyze_ScriptSourceBypassInPolicy(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		input   string
		wantIDs []string
	}{
		{
			name:  "in default-src",
			input: "default-src 'self' https://www.google.com; " + strictBoilerplate,
			wantIDs: []string{
				rule_id.ContentSecurityPolicyInsecureDefaultSrc,
				rule_id.ContentSecurityPolicyInsecureFrameSrc,
				rule_id.ContentSecurityPolicyJsonpScriptSource,
			},
		},
		{
			name:  "eval allowed in the same directive",
			input: "default-src 'self'; script-src 'self' 'unsafe-eval' https://www.googletagmanager.com; " + strictBoilerplate,
			wantIDs: []string{
				rule_id.ContentSecurityPolicyJsonpScriptSource,
				rule_id.ContentSecurityPolicyUnsafeEval,
			},
		},
		{
			name:  "eval allowed by script-src, the endpoint by script-src-elem",
			input: "default-src 'self'; script-src 'self' 'unsafe-eval'; script-src-elem 'self' https://www.googletagmanager.com; " + strictBoilerplate,
			wantIDs: []string{
				rule_id.ContentSecurityPolicyJsonpScriptSource,
				rule_id.ContentSecurityPolicyUnsafeEval,
			},
		},
		{
			name:  "eval allowed by default-src, the endpoint by script-src-elem",
			input: "default-src 'self' 'unsafe-eval'; script-src-elem 'self' https://www.googletagmanager.com; " + strictBoilerplate,
			wantIDs: []string{
				rule_id.ContentSecurityPolicyInsecureDefaultSrc,
				rule_id.ContentSecurityPolicyInsecureFrameSrc,
				rule_id.ContentSecurityPolicyJsonpScriptSource,
				rule_id.ContentSecurityPolicyUnsafeEval,
			},
		},
		{
			name:  "'unsafe-eval' where it decides nothing",
			input: "default-src 'self'; script-src-elem 'self' 'unsafe-eval' https://www.googletagmanager.com; " + strictBoilerplate,
			wantIDs: []string{
				rule_id.ContentSecurityPolicyUnsafeEval,
			},
		},
		{
			name:  "script-src deciding over default-src",
			input: "default-src 'self' 'unsafe-eval'; script-src 'self' https://www.googletagmanager.com; " + strictBoilerplate,
			wantIDs: []string{
				rule_id.ContentSecurityPolicyInsecureDefaultSrc,
				rule_id.ContentSecurityPolicyInsecureFrameSrc,
				rule_id.ContentSecurityPolicyUnsafeEval,
			},
		},
		{
			name:  "no directive deciding eval",
			input: "script-src-elem 'self' https://www.googletagmanager.com; " + strictBoilerplate,
			wantIDs: []string{
				rule_id.ContentSecurityPolicyInsecureFrameSrc,
				rule_id.ContentSecurityPolicyJsonpScriptSource,
				rule_id.ContentSecurityPolicyMissingDefaultSrc,
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			assertResults(t, testCase.input, testCase.wantIDs)
		})
	}
}

func TestParseHost(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		host string
		want *hostParts
	}{
		{name: "an ordinary host", host: "www.example.com", want: &hostParts{host: "www.example.com", registeredDomain: "example.com"}},
		{name: "a wildcard spanning a TLD", host: "*.com", want: &hostParts{host: "*.com", spansRegistrable: true}},
		{name: "a wildcard spanning a second-level suffix", host: "*.co.uk", want: &hostParts{host: "*.co.uk", spansRegistrable: true}},
		{name: "a wildcard spanning a private suffix", host: "*.github.io", want: &hostParts{host: "*.github.io", platform: "github.io", spansRegistrable: true}},
		{name: "a wildcard under a registered domain", host: "*.example.com", want: &hostParts{host: "*.example.com", registeredDomain: "example.com"}},
		{name: "a site on a private suffix", host: "example.github.io", want: &hostParts{host: "example.github.io", platform: "github.io", registeredDomain: "example.github.io"}},
		{name: "a private suffix itself", host: "github.io", want: &hostParts{host: "github.io"}},
		{name: "a service of a private suffix's operator", host: "fonts.googleapis.com", want: &hostParts{host: "fonts.googleapis.com", registeredDomain: "fonts.googleapis.com"}},
		{name: "a wildcard spanning an operator's private suffix", host: "*.googleapis.com", want: &hostParts{host: "*.googleapis.com", platform: "googleapis.com", spansRegistrable: true}},
		{name: "a suffix by a wildcard rule", host: "x.compute.amazonaws.com", want: &hostParts{host: "x.compute.amazonaws.com", platform: "compute.amazonaws.com"}},
		{name: "a name the list does not know", host: "*.localhost", want: &hostParts{host: "*.localhost", registeredDomain: "*.localhost"}},
		{name: "upper case and a trailing dot", host: "WWW.Example.COM.", want: &hostParts{host: "www.example.com", registeredDomain: "example.com"}},
		{name: "a bare wildcard", host: "*", want: nil},
		{name: "an address", host: "192.0.2.1", want: nil},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			got := parseHost(testCase.host)
			if (got == nil) != (testCase.want == nil) || (got != nil && *got != *testCase.want) {
				t.Errorf("%s: parseHost(%q) = %+v, want %+v", testCase.name, testCase.host, got, testCase.want)
			}
		})
	}
}
