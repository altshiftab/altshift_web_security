package x_frame_options

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
		{name: "DENY", input: "DENY", wantIDs: []string{rule_id.XFrameOptionsObsolete}},
		{name: "SAMEORIGIN", input: "SAMEORIGIN", wantIDs: []string{rule_id.XFrameOptionsObsolete}},
		{name: "case-insensitive deny", input: "deny", wantIDs: []string{rule_id.XFrameOptionsObsolete}},
		{name: "bad value", input: "ALLOW-FROM https://example.com", wantIDs: []string{rule_id.XFrameOptionsBadValue, rule_id.XFrameOptionsObsolete}},
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
