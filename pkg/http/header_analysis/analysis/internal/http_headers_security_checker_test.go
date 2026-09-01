package internal

import (
	"strings"
	"testing"
)

func TestMakeMissingResult_DescriptionFallback(t *testing.T) {
	t.Parallel()

	// Unknown rule id forces the description-fallback path.
	result := MakeMissingResult("unknown_rule_id_for_test", "X-Test-Header")
	if result == nil {
		t.Fatal("result = nil")
	}
	if result.Message == nil {
		t.Fatalf("result.Message = nil, want non-nil")
	}
	got := result.Message.Text
	want := "The X-Test-Header header is missing."
	if !strings.HasPrefix(got, want) {
		t.Fatalf("Message.Text = %q, want prefix %q", got, want)
	}
}
