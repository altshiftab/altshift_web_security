package analysis

import (
	"fmt"

	"github.com/altshiftab/altshift_web_security/pkg/tls/cipher_suite"
	"github.com/altshiftab/altshift_web_security/pkg/tls/connection_analysis/analysis/internal"
	"github.com/altshiftab/altshift_web_security/pkg/tls/connection_analysis/rule_id"
	"github.com/altshiftab/altshift_web_security/pkg/tls/observation"
	"github.com/altshiftab/altshift_web_security/pkg/tls/wire"
	"github.com/altshiftab/utils_go/pkg/sarif"
)

// versionRules pairs a retired version with the rule raised when a server still
// speaks it.
var versionRules = map[uint16]string{
	wire.VersionSsl30: rule_id.Ssl30Supported,
	wire.VersionTls10: rule_id.Tls10Supported,
	wire.VersionTls11: rule_id.Tls11Supported,
}

func analyzeVersions(result *observation.Observation) []*sarif.Result {
	var results []*sarif.Result

	tls13 := false

	for _, version := range result.Versions {
		if version == nil || !version.Attempted {
			continue
		}

		if !version.Accepted {
			continue
		}

		if version.Version >= wire.VersionTls13 {
			tls13 = true
		}

		ruleId, retired := versionRules[version.Version]
		if !retired {
			continue
		}

		results = append(
			results,
			internal.WithProperty(internal.MakeResult(ruleId), "version", wire.VersionName(version.Version)),
		)
	}

	if !tls13 {
		// Only worth saying when the version scan actually reached TLS 1.3. A
		// scan that ran out of budget before asking has nothing to report.
		if attempted(result, wire.VersionTls13) {
			results = append(results, internal.MakeResult(rule_id.Tls13NotSupported))
		}
	}

	return results
}

func attempted(result *observation.Observation, wanted uint16) bool {
	for _, version := range result.Versions {
		if version != nil && version.Version == wanted {
			return version.Attempted
		}
	}

	return false
}

func analyzeCipherSuites(result *observation.Observation) []*sarif.Result {
	accepted := acceptedVersions(result)
	if len(accepted) == 0 {
		return nil
	}

	// One result per category, not per suite: a server that accepts twenty suites
	// on their way out has one thing wrong with it, not twenty.
	byCategory := map[cipher_suite.Category]map[uint16]bool{}

	for _, version := range accepted {
		for _, id := range version.CipherSuites {
			category := cipher_suite.Categorize(id)

			if category != cipher_suite.CategoryInsufficient && category != cipher_suite.CategoryPhaseOut {
				continue
			}

			if byCategory[category] == nil {
				byCategory[category] = map[uint16]bool{}
			}

			byCategory[category][id] = true
		}
	}

	var results []*sarif.Result

	for _, entry := range []struct {
		category cipher_suite.Category
		ruleId   string
	}{
		{category: cipher_suite.CategoryInsufficient, ruleId: rule_id.CipherSuiteInsufficient},
		{category: cipher_suite.CategoryPhaseOut, ruleId: rule_id.CipherSuitePhaseOut},
	} {
		ids := keysOf(byCategory[entry.category])
		if len(ids) == 0 {
			continue
		}

		names := internal.SuiteNames(ids)

		results = append(
			results,
			internal.WithProperty(
				internal.WithMessage(
					internal.MakeResult(entry.ruleId),
					fmt.Sprintf(
						"The server negotiates %d cipher suite(s) the policy considers %s: %s. %s",
						len(names),
						entry.category,
						joinNames(names),
						shortReason(entry.category),
					),
				),
				"suites",
				names,
			),
		)
	}

	return results
}

func shortReason(category cipher_suite.Category) string {
	if category == cipher_suite.CategoryInsufficient {
		return "Depending on the suite this means broken encryption, an effective key length too short to matter, " +
			"no encryption at all, no authentication of the peer, or no forward secrecy -- which leaves every " +
			"recorded past session readable to whoever eventually obtains the server's private key."
	}

	return "They are not broken and not urgent, but they are no longer the ones to be adding."
}

func analyzeCipherSuiteOrder(result *observation.Observation) []*sarif.Result {
	order := result.Order
	if order == nil || !order.Tested {
		return nil
	}

	if !order.Applicable {
		return []*sarif.Result{
			internal.MakeNotApplicableResult(
				"cipher suite order",
				"the server accepts only TLS 1.3, whose suites are all acceptable, so their order does not matter",
			),
		}
	}

	if order.ServerEnforces == nil {
		return []*sarif.Result{
			internal.MakeNotDeterminedResult("cipher suite order", "the server did not answer the ordering probe"),
		}
	}

	if !*order.ServerEnforces {
		return []*sarif.Result{internal.MakeResult(rule_id.CipherSuiteOrderNotEnforced)}
	}

	if len(order.Violation) != 2 {
		return nil
	}

	preferred := order.Violation[0]
	overlooked := order.Violation[1]

	return []*sarif.Result{
		internal.WithProperty(
			internal.WithProperty(
				internal.WithMessage(
					internal.MakeResult(rule_id.CipherSuiteOrderViolation),
					fmt.Sprintf(
						"At %s the server prefers %s, which the policy considers %s, over %s, which it considers %s "+
							"and which the server also supports. A client offering both is given the weaker one, so "+
							"supporting the stronger achieves nothing for the connections that matter.",
						wire.VersionName(order.ViolationVersion),
						cipher_suite.Name(preferred),
						cipher_suite.Categorize(preferred),
						cipher_suite.Name(overlooked),
						cipher_suite.Categorize(overlooked),
					),
				),
				"preferred",
				cipher_suite.Name(preferred),
			),
			"overlooked",
			cipher_suite.Name(overlooked),
		),
	}
}

func keysOf(set map[uint16]bool) []uint16 {
	ids := make([]uint16, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}

	return ids
}

func joinNames(names []string) string {
	joined := ""

	for index, name := range names {
		if index != 0 {
			joined += ", "
		}

		joined += name
	}

	return joined
}
