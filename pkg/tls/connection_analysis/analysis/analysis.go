// Package analysis turns what a probe saw into SARIF findings.
//
// It opens no sockets. Everything it reports comes from an observation.Observation,
// which means a test builds one by hand and asserts on the findings, and the policy
// can be argued about without a server to argue against.
//
// A check that passes says nothing, as in the header analysis: a clean server
// produces an empty run. The exception is a check that could not be run, which emits
// a result of its own -- silence there would be read as a pass, and the whole point
// of a report like this is that the reader can tell the difference.
package analysis

import (
	"github.com/altshiftab/altshift_web_security/pkg/tls/connection_analysis/analysis/internal"
	"github.com/altshiftab/altshift_web_security/pkg/tls/connection_analysis/rule_id_mappings"
	"github.com/altshiftab/altshift_web_security/pkg/tls/observation"
	"github.com/altshiftab/utils_go/pkg/sarif"
)

const (
	ToolName           = "tls_connection_security_checker"
	ToolInformationUri = "https://github.com/altshiftab/altshift_web_security"
)

// analyzer is one check: it reads the observation and says what is wrong.
type analyzer struct {
	name    string
	analyze func(*observation.Observation) []*sarif.Result
}

// analyzers are run in this order, so a run's results are stable.
var analyzers = []*analyzer{
	{name: "tls_version", analyze: analyzeVersions},
	{name: "cipher_suites", analyze: analyzeCipherSuites},
	{name: "cipher_suite_order", analyze: analyzeCipherSuiteOrder},
	{name: "key_exchange_parameters", analyze: analyzeKeyExchangeParameters},
	{name: "key_exchange_hash", analyze: analyzeKeyExchangeHash},
	{name: "compression", analyze: analyzeCompression},
	{name: "secure_renegotiation", analyze: analyzeSecureRenegotiation},
	{name: "client_renegotiation", analyze: analyzeClientRenegotiation},
	{name: "zero_rtt", analyze: analyzeZeroRtt},
	{name: "ocsp_stapling", analyze: analyzeOcspStapling},
	{name: "extended_master_secret", analyze: analyzeExtendedMasterSecret},
}

// AnalyzeConnection reports on what a probe found.
func AnalyzeConnection(result *observation.Observation) (*sarif.Run, error) {
	if result == nil {
		return nil, nil
	}

	var allResults []*sarif.Result

	for _, analyzer := range analyzers {
		allResults = append(allResults, analyzer.analyze(result)...)
	}

	// A phase the probe abandoned is reported once, here, rather than by each
	// check that would have used it: the checks cannot tell the difference between
	// a phase that was cut short and one that found nothing, and the probe can.
	for _, phase := range result.Incomplete {
		if phase == nil {
			continue
		}

		allResults = append(allResults, internal.MakeNotDeterminedResult(phase.Name, phase.Reason))
	}

	return &sarif.Run{
		Tool: &sarif.Tool{
			Driver: &sarif.ToolComponent{
				Name:           ToolName,
				InformationUri: ToolInformationUri,
				Rules:          buildRules(allResults),
			},
		},
		Results: allResults,
	}, nil
}

func buildRules(results []*sarif.Result) []*sarif.ReportingDescriptor {
	seen := map[string]bool{}

	var rules []*sarif.ReportingDescriptor

	for _, result := range results {
		if result == nil || result.RuleId == "" || seen[result.RuleId] {
			continue
		}

		seen[result.RuleId] = true

		rule := &sarif.ReportingDescriptor{Id: result.RuleId}

		if title := rule_id_mappings.RuleIdToTitle[result.RuleId]; title != "" {
			rule.ShortDescription = &sarif.MultiformatMessageString{Text: title}
		}

		if description := rule_id_mappings.RuleIdToDescription[result.RuleId]; description != "" {
			rule.FullDescription = &sarif.MultiformatMessageString{Text: description}
		}

		rules = append(rules, rule)
	}

	return rules
}

// acceptedVersions are the versions the server was found to speak.
func acceptedVersions(result *observation.Observation) []*observation.Version {
	var accepted []*observation.Version

	for _, version := range result.Versions {
		if version != nil && version.Accepted {
			accepted = append(accepted, version)
		}
	}

	return accepted
}
