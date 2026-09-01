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

func analyzeKeyExchangeParameters(result *observation.Observation) []*sarif.Result {
	groups := result.Groups
	if groups == nil || !groups.Tested {
		return nil
	}

	var results []*sarif.Result

	// What the server chose, per version.
	chosen := map[uint16]bool{}
	for _, group := range groups.Selected {
		chosen[group] = true
	}

	for _, entry := range []struct {
		category cipher_suite.Category
		ruleId   string
	}{
		{category: cipher_suite.CategoryInsufficient, ruleId: rule_id.KeyExchangeGroupInsufficient},
		{category: cipher_suite.CategoryPhaseOut, ruleId: rule_id.KeyExchangeGroupPhaseOut},
	} {
		var named []string

		for group := range chosen {
			if cipher_suite.CategorizeGroup(group) == entry.category {
				named = append(named, cipher_suite.GroupName(group))
			}
		}

		if len(named) == 0 {
			continue
		}

		results = append(
			results,
			internal.WithProperty(
				internal.WithMessage(
					internal.MakeResult(entry.ruleId),
					fmt.Sprintf(
						"The server does its key exchange over %s, which the policy considers %s.",
						joinNames(sortedStrings(named)),
						entry.category,
					),
				),
				"groups",
				sortedStrings(named),
			),
		)
	}

	// A group the server merely tolerates matters as much as the one it prefers:
	// a client offering nothing better, or an attacker stripping the better ones
	// out of a hello in transit, gets what the server will stoop to.
	if len(groups.WeakAccepted) != 0 {
		var named []string
		for _, group := range groups.WeakAccepted {
			named = append(named, cipher_suite.GroupName(group))
		}

		results = append(
			results,
			internal.WithProperty(
				internal.WithMessage(
					internal.MakeResult(rule_id.KeyExchangeGroupWeakAccepted),
					fmt.Sprintf(
						"Offered only weak key exchange groups, the server agreed to %s rather than refusing the "+
							"connection. What a server prefers matters less than what it will accept.",
						joinNames(sortedStrings(named)),
					),
				),
				"groups",
				sortedStrings(named),
			),
		)
	}

	results = append(results, analyzeFiniteField(result)...)

	return results
}

// analyzeFiniteField reports a finite-field group smaller than the policy allows.
//
// Only the size and the generator are visible in a handshake; whether the group is
// one of the standard ones from RFC 7919, or a custom one with a hidden weakness, is
// not something the wire says. A large custom group is reported as acceptable here
// where the policy would want it looked at.
func analyzeFiniteField(result *observation.Observation) []*sarif.Result {
	smallest := 0
	version := uint16(0)

	for _, accepted := range acceptedVersions(result) {
		if accepted.FiniteField == nil || accepted.FiniteField.PrimeBits == 0 {
			continue
		}

		if smallest == 0 || accepted.FiniteField.PrimeBits < smallest {
			smallest = accepted.FiniteField.PrimeBits
			version = accepted.Version
		}
	}

	if smallest == 0 || smallest >= cipher_suite.MinimumFiniteFieldPrimeBits {
		return nil
	}

	return []*sarif.Result{
		internal.WithProperty(
			internal.WithProperty(
				internal.WithMessage(
					internal.MakeResult(rule_id.KeyExchangeFiniteFieldSmall),
					fmt.Sprintf(
						"At %s the server does its key exchange over a %d-bit finite-field group, below the %d bits "+
							"the policy requires. A group this size is within reach of an adversary who precomputes "+
							"against it once and then reads every session that used it, which is the Logjam attack.",
						wire.VersionName(version),
						smallest,
						cipher_suite.MinimumFiniteFieldPrimeBits,
					),
				),
				"primeBits",
				smallest,
			),
			"version",
			wire.VersionName(version),
		),
	}
}

func analyzeKeyExchangeHash(result *observation.Observation) []*sarif.Result {
	signature := result.Signature
	if signature == nil || !signature.Tested {
		return nil
	}

	var results []*sarif.Result

	for _, entry := range []struct {
		accepted *bool
		ruleId   string
		hash     string
	}{
		{accepted: signature.Sha1Accepted, ruleId: rule_id.KeyExchangeHashSha1, hash: "SHA-1"},
		{accepted: signature.Sha224Accepted, ruleId: rule_id.KeyExchangeHashSha224, hash: "SHA-224"},
	} {
		if entry.accepted == nil {
			results = append(
				results,
				internal.MakeNotDeterminedResult(
					"key exchange hash ("+entry.hash+")",
					"the server did not sign a key exchange this could read",
				),
			)

			continue
		}

		if !*entry.accepted {
			continue
		}

		results = append(results, internal.MakeResult(entry.ruleId))
	}

	// What it actually chose, when nothing is wrong with it, is worth recording on
	// the results that are there rather than as a finding of its own.
	return results
}

func sortedStrings(values []string) []string {
	sorted := make([]string, len(values))
	copy(sorted, values)

	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && sorted[j] < sorted[j-1]; j-- {
			sorted[j], sorted[j-1] = sorted[j-1], sorted[j]
		}
	}

	return sorted
}
