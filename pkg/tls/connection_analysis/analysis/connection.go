package analysis

import (
	"fmt"

	"github.com/altshiftab/altshift_web_security/pkg/tls/connection_analysis/analysis/internal"
	"github.com/altshiftab/altshift_web_security/pkg/tls/connection_analysis/rule_id"
	"github.com/altshiftab/altshift_web_security/pkg/tls/observation"
	"github.com/altshiftab/altshift_web_security/pkg/tls/wire"
	"github.com/altshiftab/utils_go/pkg/sarif"
)

func analyzeCompression(result *observation.Observation) []*sarif.Result {
	compression := result.Compression
	if compression == nil || !compression.Tested {
		return nil
	}

	if !compression.Applicable {
		return []*sarif.Result{
			internal.MakeNotApplicableResult(
				"TLS compression",
				"the server accepts only TLS 1.3, which removed record compression from the protocol",
			),
		}
	}

	if compression.Selected == nil {
		return []*sarif.Result{
			internal.MakeNotDeterminedResult("TLS compression", "the server did not answer the compression probe"),
		}
	}

	if *compression.Selected == 0 {
		return nil
	}

	return []*sarif.Result{
		internal.WithProperty(
			internal.MakeResult(rule_id.CompressionEnabled),
			"compressionMethod",
			int(*compression.Selected),
		),
	}
}

func analyzeSecureRenegotiation(result *observation.Observation) []*sarif.Result {
	renegotiation := result.Renegotiation
	if renegotiation == nil {
		return nil
	}

	if renegotiation.SecureSupported == nil {
		// Nothing below TLS 1.3 was accepted, so there is no renegotiation to
		// secure. This is the good outcome rather than an unanswered question.
		if onlyTls13(result) {
			return []*sarif.Result{
				internal.MakeNotApplicableResult(
					"secure renegotiation",
					"the server accepts only TLS 1.3, which removed renegotiation from the protocol",
				),
			}
		}

		return []*sarif.Result{
			internal.MakeNotDeterminedResult("secure renegotiation", "no server hello carried the answer"),
		}
	}

	if *renegotiation.SecureSupported {
		return nil
	}

	return []*sarif.Result{internal.MakeResult(rule_id.SecureRenegotiationUnsupported)}
}

// analyzeClientRenegotiation reports the one renegotiation check this cannot make.
//
// Testing it means completing a handshake and then sending a ClientHello inside the
// encrypted channel, which needs a TLS record layer -- a key schedule, a cipher, and
// sequence numbers -- that this deliberately does not implement. The exception is a
// server that accepts only TLS 1.3, where renegotiation was removed from the
// protocol: there the answer is known without asking.
func analyzeClientRenegotiation(result *observation.Observation) []*sarif.Result {
	renegotiation := result.Renegotiation
	if renegotiation == nil {
		return nil
	}

	if renegotiation.ClientInitiatedPossible != nil && !*renegotiation.ClientInitiatedPossible {
		return []*sarif.Result{
			internal.MakeNotApplicableResult(
				"client-initiated renegotiation",
				"the server accepts only TLS 1.3, which removed renegotiation from the protocol, so it cannot be "+
					"initiated at all",
			),
		}
	}

	reason := renegotiation.ClientInitiatedReason
	if reason == "" {
		reason = "it was not attempted"
	}

	return []*sarif.Result{internal.MakeNotDeterminedResult("client-initiated renegotiation", reason)}
}

func analyzeZeroRtt(result *observation.Observation) []*sarif.Result {
	session := result.Session
	if session == nil {
		return nil
	}

	if !session.Established {
		reason := session.Error
		if reason == "" {
			reason = "no session could be established"
		}

		return []*sarif.Result{internal.MakeNotDeterminedResult("0-RTT", reason)}
	}

	earlyData := session.EarlyData
	if earlyData == nil {
		return []*sarif.Result{internal.MakeNotDeterminedResult("0-RTT", "the session ticket was not examined")}
	}

	if !earlyData.Determined {
		reason := earlyData.Reason
		if reason == "" {
			reason = "the session ticket could not be read"
		}

		return []*sarif.Result{internal.MakeNotDeterminedResult("0-RTT", reason)}
	}

	if earlyData.MaxSize == nil {
		return nil
	}

	return []*sarif.Result{
		internal.WithProperty(
			internal.WithMessage(
				internal.MakeResult(rule_id.ZeroRttEnabled),
				fmt.Sprintf(
					"The server offers 0-RTT early data, accepting up to %d bytes in the first flight. That data is "+
						"not covered by the anti-replay protection the rest of the connection has, so an attacker "+
						"who captures it can send it again and have it acted on twice.",
					*earlyData.MaxSize,
				),
			),
			"maxEarlyDataSize",
			int(*earlyData.MaxSize),
		),
	}
}

func analyzeOcspStapling(result *observation.Observation) []*sarif.Result {
	session := result.Session
	if session == nil {
		return nil
	}

	if !session.Established {
		reason := session.Error
		if reason == "" {
			reason = "no session could be established"
		}

		return []*sarif.Result{internal.MakeNotDeterminedResult("OCSP stapling", reason)}
	}

	if session.OcspStapled {
		return nil
	}

	return []*sarif.Result{internal.MakeResult(rule_id.OcspStaplingMissing)}
}

func analyzeExtendedMasterSecret(result *observation.Observation) []*sarif.Result {
	accepted := acceptedVersions(result)
	if len(accepted) == 0 {
		return nil
	}

	if onlyTls13(result) {
		return []*sarif.Result{
			internal.MakeNotApplicableResult(
				"extended master secret",
				"the server accepts only TLS 1.3, whose key schedule binds the handshake in already",
			),
		}
	}

	var without []string

	for _, version := range accepted {
		if version.Version >= wire.VersionTls13 {
			continue
		}

		if version.ExtendedMasterSecret == nil || *version.ExtendedMasterSecret {
			continue
		}

		without = append(without, wire.VersionName(version.Version))
	}

	if len(without) == 0 {
		return nil
	}

	return []*sarif.Result{
		internal.WithProperty(internal.MakeResult(rule_id.ExtendedMasterSecretUnsupported), "versions", without),
	}
}

// onlyTls13 reports whether every version the server accepted was TLS 1.3, which is
// what makes three of these checks moot rather than unanswered.
func onlyTls13(result *observation.Observation) bool {
	accepted := acceptedVersions(result)
	if len(accepted) == 0 {
		return false
	}

	for _, version := range accepted {
		if version.Version < wire.VersionTls13 {
			return false
		}
	}

	return true
}
