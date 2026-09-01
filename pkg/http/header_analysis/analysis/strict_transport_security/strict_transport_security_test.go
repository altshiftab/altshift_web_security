package strict_transport_security

import (
	"slices"
	"testing"

	"github.com/altshiftab/altshift_web_security/pkg/http/header_analysis/rule_id"
	"github.com/altshiftab/utils_go/pkg/sarif"
)

func TestAnalyze(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		input   string
		wantIDs []string
	}{
		{
			name:    "empty",
			input:   "",
			wantIDs: nil,
		},
		{
			name:    "fully strict policy",
			input:   "max-age=31536000; includeSubDomains; preload",
			wantIDs: nil,
		},
		{
			name:  "missing preload",
			input: "max-age=31536000; includeSubDomains",
			wantIDs: []string{
				rule_id.StrictTransportSecurityMissingPreload,
			},
		},
		{
			name:  "missing includeSubDomains and preload",
			input: "max-age=31536000",
			wantIDs: []string{
				rule_id.StrictTransportSecurityMissingIncludeSubdomains,
				rule_id.StrictTransportSecurityMissingPreload,
			},
		},
		{
			name:  "low max-age",
			input: "max-age=60; includeSubDomains; preload",
			wantIDs: []string{
				rule_id.StrictTransportSecurityMissingOrLowMaxAge,
			},
		},
		{
			name:  "max-age zero",
			input: "max-age=0",
			wantIDs: []string{
				rule_id.StrictTransportSecurityMissingIncludeSubdomains,
				rule_id.StrictTransportSecurityMissingOrLowMaxAge,
				rule_id.StrictTransportSecurityMissingPreload,
			},
		},
		{
			name:  "syntax error",
			input: "this is not a valid policy@@@",
			wantIDs: []string{
				rule_id.InvalidStrictTransportSecurity,
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := Analyze(tc.input)
			if err != nil {
				t.Fatalf("Analyze(%q) err = %v", tc.input, err)
			}
			gotIDs := resultIDs(got)
			if !slices.Equal(gotIDs, tc.wantIDs) {
				t.Fatalf("Analyze(%q) IDs = %v, want %v", tc.input, gotIDs, tc.wantIDs)
			}
		})
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
