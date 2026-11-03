package content_security_policy

import (
	"fmt"
	"maps"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/altshiftab/altshift_web_security/pkg/http/header_analysis/rule_id"
	"github.com/altshiftab/utils_go/pkg/sarif"
)

// cspBypassScriptSource finds the script URL in a CSPBypass payload.
var cspBypassScriptSource = regexp.MustCompile(`src=["']?((?:https?:)?//[^"'\s>]+)`)

// readCspBypass returns the domains of CSPBypass's data.tsv, and for each payload loading a script, a source allowing
// the directory that script is in.
func readCspBypass(data string) (domains []string, directorySources []string) { //nolint:nonamedreturns // two lists of strings
	seenDomains := map[string]bool{}
	seenSources := map[string]bool{}

	for index, line := range strings.Split(data, "\n") {
		// The header names the columns; a few rows separate them with spaces rather than a tab.
		fields := strings.Fields(line)
		if index == 0 || len(fields) == 0 {
			continue
		}

		if domain := strings.ToLower(fields[0]); strings.Contains(domain, ".") && !strings.ContainsAny(domain, "<>\"'") {
			if !seenDomains[domain] {
				seenDomains[domain] = true
				domains = append(domains, domain)
			}
		}

		match := cspBypassScriptSource.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		scriptUrl, err := url.Parse(strings.TrimPrefix(strings.TrimPrefix(match[1], "https:"), "http:"))
		if err != nil || scriptUrl.Host == "" {
			continue
		}
		directory := scriptUrl.EscapedPath()
		directory = directory[:strings.LastIndex(directory, "/")+1]
		if directory == "" {
			directory = "/"
		}
		source := "https://" + strings.ToLower(scriptUrl.Host) + directory
		if !seenSources[source] {
			seenSources[source] = true
			directorySources = append(directorySources, source)
		}
	}

	return domains, directorySources
}

// TestCspBypassCoverage reports how many of CSPBypass's bypasses the source rules catch, allowed in script-src. Its
// data is GPL-3.0 and is not vendored: set CSPBYPASS_DATA to a local copy of its data.tsv to run this, and
// CSPBYPASS_VERBOSE to list what is missed.
func TestCspBypassCoverage(t *testing.T) {
	t.Parallel()

	dataPath := os.Getenv("CSPBYPASS_DATA")
	if dataPath == "" {
		t.Skip("CSPBYPASS_DATA does not name a copy of CSPBypass's data.tsv")
	}

	data, err := os.ReadFile(dataPath) //nolint:gosec // the path is the one the person running the check named
	if err != nil {
		t.Fatalf("read %s: %v", dataPath, err)
	}

	domains, directorySources := readCspBypass(string(data))
	if len(domains) == 0 {
		t.Fatalf("no domains in %s", dataPath)
	}

	sources := make([]string, 0, len(domains))
	for _, domain := range domains {
		sources = append(sources, "https://"+domain)
	}

	for _, set := range []struct {
		name    string
		sources []string
	}{
		{name: "domains", sources: sources},
		{name: "payload directories", sources: directorySources},
	} {
		byRule := map[string]int{}
		var flagged, flaggedAsErrors, unparsed int
		var missed []string

		for _, source := range set.sources {
			results, err := Analyze("default-src 'self'; script-src " + source + "; " + strictBoilerplate)
			if err != nil {
				t.Fatalf("Analyze %s: %v", source, err)
			}

			var ruleId string
			var level sarif.Level
			for _, result := range results {
				if result.RuleId == rule_id.InvalidContentSecurityPolicy {
					unparsed++
				}
				if slices.Contains(sourceRuleIds, result.RuleId) {
					ruleId, level = result.RuleId, result.Level
				}
			}

			if ruleId == "" {
				missed = append(missed, source)
				continue
			}
			flagged++
			byRule[ruleId]++
			if level == sarif.LevelError {
				flaggedAsErrors++
			}
		}

		var breakdown []string
		for _, ruleId := range slices.Sorted(maps.Keys(byRule)) {
			breakdown = append(breakdown, fmt.Sprintf("%s %d", ruleId, byRule[ruleId]))
		}
		t.Logf(
			"%s: %d of %d flagged, %d of them as errors; %d not parsed as a policy\n%s",
			set.name, flagged, len(set.sources), flaggedAsErrors, unparsed, strings.Join(breakdown, "\n"),
		)
		if os.Getenv("CSPBYPASS_VERBOSE") != "" {
			t.Logf("%s missed:\n%s", set.name, strings.Join(missed, "\n"))
		}
	}
}

func TestReadCspBypass(t *testing.T) {
	t.Parallel()

	data := "Domain\tCode\n" +
		"a.example.com\t<script src=\"https://a.example.com/x/jsonp?callback=alert(1)\"></script>\n" +
		"b.example.com  <script src=\"//b.example.com/y.js\"></script>\n" +
		"a.example.com\t<script src='https://a.example.com/x/other'></script>\n" +
		"<div ng-app>{{x}}</div>\n"

	domains, directorySources := readCspBypass(data)

	wantDomains := []string{"a.example.com", "b.example.com"}
	wantSources := []string{"https://a.example.com/x/", "https://b.example.com/"}
	if !slices.Equal(domains, wantDomains) || !slices.Equal(directorySources, wantSources) {
		t.Errorf("readCspBypass = %v, %v, want %v, %v", domains, directorySources, wantDomains, wantSources)
	}
}
