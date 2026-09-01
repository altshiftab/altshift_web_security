package cross_origin_resource_policy

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
		{name: "empty", input: "", wantIDs: nil},
		{name: "same-origin", input: "same-origin", wantIDs: nil},
		{name: "same-site", input: "same-site", wantIDs: nil},
		{name: "cross-origin", input: "cross-origin", wantIDs: []string{rule_id.CrossOriginResourcePolicyCrossOrigin}},
		{name: "case-insensitive cross-origin", input: "CROSS-ORIGIN", wantIDs: []string{rule_id.CrossOriginResourcePolicyCrossOrigin}},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := resultIDs(Analyze(tc.input))
			if !slices.Equal(got, tc.wantIDs) {
				t.Fatalf("Analyze(%q) IDs = %v, want %v", tc.input, got, tc.wantIDs)
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
