package analysis

import (
	"strings"
	"testing"

	"github.com/altshiftab/altshift_web_security/pkg/tls/connection_analysis/rule_id"
	"github.com/altshiftab/altshift_web_security/pkg/tls/observation"
	"github.com/altshiftab/altshift_web_security/pkg/tls/wire"
	"github.com/altshiftab/utils_go/pkg/sarif"
)

func pointerTo[T any](value T) *T {
	return &value
}

// acceptedVersion is a version the server was found to speak, with the fields a
// clean TLS 1.2 answer would carry.
func acceptedVersion(version uint16, suites ...uint16) *observation.Version {
	return &observation.Version{
		Version:              version,
		Attempted:            true,
		Accepted:             true,
		CipherSuites:         suites,
		CipherSuitesComplete: true,
		ExtendedMasterSecret: pointerTo(true),
		SecureRenegotiation:  pointerTo(true),
	}
}

func refusedVersion(version uint16) *observation.Version {
	return &observation.Version{Version: version, Attempted: true}
}

// cleanObservation is a server with nothing wrong with it, which must produce no
// findings at all. Every case below is this with one thing changed, so a finding
// that appears is caused by that change and nothing else.
func cleanObservation() *observation.Observation {
	return &observation.Observation{
		Target: &observation.Target{Host: "example.test", Port: 443},
		Versions: []*observation.Version{
			refusedVersion(wire.VersionSsl30),
			refusedVersion(wire.VersionTls10),
			refusedVersion(wire.VersionTls11),
			acceptedVersion(wire.VersionTls12, 0xc02f, 0xc030),
			acceptedVersion(wire.VersionTls13, 0x1302, 0x1303),
		},
		Groups: &observation.Groups{
			Tested:   true,
			Selected: map[uint16]uint16{wire.VersionTls12: wire.GroupX25519, wire.VersionTls13: wire.GroupX25519},
		},
		Signature: &observation.Signature{
			Tested:         true,
			Sha1Accepted:   pointerTo(false),
			Sha224Accepted: pointerTo(false),
		},
		Compression:   &observation.Compression{Tested: true, Applicable: true, Selected: pointerTo(uint8(0))},
		Renegotiation: &observation.Renegotiation{SecureSupported: pointerTo(true)},
		Order:         &observation.Order{Tested: true, Applicable: true, ServerEnforces: pointerTo(true)},
		Session:       &observation.Session{Established: true, Version: 0x0304, OcspStapled: true},
	}
}

// ruleIds is what a run reported, for comparing against what it should have.
func ruleIds(run *sarif.Run) []string {
	var ids []string
	for _, result := range run.Results {
		ids = append(ids, result.RuleId)
	}

	return ids
}

func holds(ids []string, wanted string) bool {
	for _, id := range ids {
		if id == wanted {
			return true
		}
	}

	return false
}

// A clean server draws no findings. Anything failing here is a check firing on a
// server with nothing wrong with it, which would make every real report
// untrustworthy.
//
// It is not silent, though: client-initiated renegotiation cannot be tested at all
// below TLS 1.3, and says so every time. That is the design -- an untested check
// that said nothing would be indistinguishable from one that passed.
func TestAnalyzeConnectionFindsNothingWrongWithACleanServer(t *testing.T) {
	t.Parallel()

	clean := cleanObservation()
	clean.Session.EarlyData = &observation.EarlyData{Determined: true}

	run, err := AnalyzeConnection(clean)
	if err != nil {
		t.Fatalf("analyze connection: %v", err)
	}

	if run == nil {
		t.Fatal("no run was produced")
	}

	for _, result := range run.Results {
		if result.Kind == sarif.KindFail {
			t.Errorf("a clean server was reported for %q: %s", result.RuleId, result.Message.Text)

			continue
		}

		if result.RuleId != rule_id.CheckNotDetermined {
			t.Errorf("a clean server produced %q, which is neither a finding nor an undetermined check", result.RuleId)
		}
	}
}

func TestAnalyzeConnection(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		// mutate turns the clean observation into the one under test.
		mutate func(*observation.Observation)
		// expected are the rule ids the run must hold, and unexpected the ones it
		// must not.
		expected   []string
		unexpected []string
	}{
		{
			name: "an old server",
			mutate: func(result *observation.Observation) {
				result.Versions[0] = acceptedVersion(wire.VersionSsl30, 0x002f)
				result.Versions[1] = acceptedVersion(wire.VersionTls10, 0x002f)
				result.Versions[2] = acceptedVersion(wire.VersionTls11, 0x002f)
			},
			expected: []string{
				rule_id.Ssl30Supported,
				rule_id.Tls10Supported,
				rule_id.Tls11Supported,
				rule_id.CipherSuiteInsufficient,
			},
		},
		{
			name: "no tls 1.3",
			mutate: func(result *observation.Observation) {
				result.Versions[4] = refusedVersion(wire.VersionTls13)
			},
			expected: []string{rule_id.Tls13NotSupported},
		},
		{
			// A version never asked about is not a version found absent.
			name: "tls 1.3 was never attempted",
			mutate: func(result *observation.Observation) {
				result.Versions[4] = &observation.Version{Version: wire.VersionTls13}
			},
			unexpected: []string{rule_id.Tls13NotSupported},
		},
		{
			name: "insufficient and phase-out suites",
			mutate: func(result *observation.Observation) {
				// Static RSA (no forward secrecy) and a CBC suite on its way out.
				result.Versions[3] = acceptedVersion(wire.VersionTls12, 0xc02f, 0x009c, 0xc027)
			},
			expected: []string{rule_id.CipherSuiteInsufficient, rule_id.CipherSuitePhaseOut},
		},
		{
			name: "the server follows the client's cipher order",
			mutate: func(result *observation.Observation) {
				result.Order.ServerEnforces = pointerTo(false)
			},
			expected: []string{rule_id.CipherSuiteOrderNotEnforced},
		},
		{
			name: "the server prefers a weaker suite over a stronger one",
			mutate: func(result *observation.Observation) {
				result.Order.Violation = []uint16{0x009c, 0xc02f}
				result.Order.ViolationVersion = wire.VersionTls12
			},
			expected: []string{rule_id.CipherSuiteOrderViolation},
		},
		{
			name: "a phase-out key exchange group",
			mutate: func(result *observation.Observation) {
				result.Groups.Selected[wire.VersionTls12] = wire.GroupFfdhe2048
			},
			expected: []string{rule_id.KeyExchangeGroupPhaseOut},
		},
		{
			name: "an insufficient key exchange group",
			mutate: func(result *observation.Observation) {
				result.Groups.Selected[wire.VersionTls12] = 0xdead
			},
			expected: []string{rule_id.KeyExchangeGroupInsufficient},
		},
		{
			name: "a weak group the server merely tolerates",
			mutate: func(result *observation.Observation) {
				result.Groups.WeakAccepted = []uint16{wire.GroupFfdhe2048}
			},
			expected: []string{rule_id.KeyExchangeGroupWeakAccepted},
		},
		{
			name: "a finite-field group that is too small",
			mutate: func(result *observation.Observation) {
				result.Versions[3].FiniteField = &observation.FiniteField{PrimeBits: 1024, GeneratorIsTwo: true}
			},
			expected: []string{rule_id.KeyExchangeFiniteFieldSmall},
		},
		{
			name: "a finite-field group that is large enough",
			mutate: func(result *observation.Observation) {
				result.Versions[3].FiniteField = &observation.FiniteField{PrimeBits: 2048, GeneratorIsTwo: true}
			},
			unexpected: []string{rule_id.KeyExchangeFiniteFieldSmall},
		},
		{
			name: "the key exchange is signed with sha-1",
			mutate: func(result *observation.Observation) {
				result.Signature.Sha1Accepted = pointerTo(true)
			},
			expected: []string{rule_id.KeyExchangeHashSha1},
		},
		{
			name: "the key exchange is signed with sha-224",
			mutate: func(result *observation.Observation) {
				result.Signature.Sha224Accepted = pointerTo(true)
			},
			expected: []string{rule_id.KeyExchangeHashSha224},
		},
		{
			name: "record compression is on",
			mutate: func(result *observation.Observation) {
				result.Compression.Selected = pointerTo(uint8(1))
			},
			expected: []string{rule_id.CompressionEnabled},
		},
		{
			name: "secure renegotiation is unsupported",
			mutate: func(result *observation.Observation) {
				result.Renegotiation.SecureSupported = pointerTo(false)
			},
			expected: []string{rule_id.SecureRenegotiationUnsupported},
		},
		{
			name: "the extended master secret is unsupported",
			mutate: func(result *observation.Observation) {
				result.Versions[3].ExtendedMasterSecret = pointerTo(false)
			},
			expected: []string{rule_id.ExtendedMasterSecretUnsupported},
		},
		{
			name: "0-rtt is offered",
			mutate: func(result *observation.Observation) {
				result.Session.EarlyData = &observation.EarlyData{Determined: true, MaxSize: pointerTo(uint32(14336))}
			},
			expected: []string{rule_id.ZeroRttEnabled},
		},
		{
			// A ticket carrying the extension with a size of zero is not an offer.
			name: "0-rtt is advertised at zero bytes",
			mutate: func(result *observation.Observation) {
				result.Session.EarlyData = &observation.EarlyData{Determined: true}
			},
			unexpected: []string{rule_id.ZeroRttEnabled},
		},
		{
			name: "nothing is stapled",
			mutate: func(result *observation.Observation) {
				result.Session.OcspStapled = false
			},
			expected: []string{rule_id.OcspStaplingMissing},
		},
		{
			name: "a phase the probe abandoned",
			mutate: func(result *observation.Observation) {
				result.Incomplete = []*observation.Phase{
					{Name: "cipher_suites", Reason: "the connection budget was exhausted"},
				}
			},
			expected: []string{rule_id.CheckNotDetermined},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			result := cleanObservation()
			result.Session.EarlyData = &observation.EarlyData{Determined: true}

			testCase.mutate(result)

			run, err := AnalyzeConnection(result)
			if err != nil {
				t.Fatalf("analyze connection: %v", err)
			}

			ids := ruleIds(run)

			for _, wanted := range testCase.expected {
				if !holds(ids, wanted) {
					t.Errorf("%q was not reported; the run holds %v", wanted, ids)
				}
			}

			for _, unwanted := range testCase.unexpected {
				if holds(ids, unwanted) {
					t.Errorf("%q was reported, and should not have been", unwanted)
				}
			}
		})
	}
}

// A server that speaks only TLS 1.3 has no compression, no renegotiation and no
// extended master secret to get wrong. Saying so is different from saying it passed,
// and different again from saying nothing.
func TestAnalyzeConnectionAgainstTls13OnlyServer(t *testing.T) {
	t.Parallel()

	result := cleanObservation()
	result.Versions[3] = refusedVersion(wire.VersionTls12)
	result.Compression = &observation.Compression{Tested: true, Applicable: false}
	result.Order = &observation.Order{Tested: true, Applicable: false}
	result.Renegotiation = &observation.Renegotiation{ClientInitiatedPossible: pointerTo(false)}
	result.Session.EarlyData = &observation.EarlyData{Determined: true}

	run, err := AnalyzeConnection(result)
	if err != nil {
		t.Fatalf("analyze connection: %v", err)
	}

	if run == nil {
		t.Fatal("no run was produced")
	}

	notApplicable := 0

	for _, sarifResult := range run.Results {
		if sarifResult.Kind == sarif.KindNotApplicable {
			notApplicable++
		}

		if sarifResult.RuleId != rule_id.CheckNotDetermined {
			t.Errorf("a TLS 1.3-only server was reported for %q", sarifResult.RuleId)
		}
	}

	// Compression, cipher order, secure renegotiation, client-initiated
	// renegotiation and extended master secret all have no subject here.
	if notApplicable < 5 {
		t.Errorf("only %d checks were reported as not applicable, want at least 5", notApplicable)
	}
}

// A check that could not be run must say so. Silence would be read as a pass, and
// the difference is the whole value of the report.
func TestUndeterminedChecksAreReported(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		// mutate removes the answer to one check.
		mutate func(*observation.Observation)
		// expectedCheck is the check property the result must carry.
		expectedCheck string
	}{
		{
			name: "no session was established",
			mutate: func(result *observation.Observation) {
				result.Session = &observation.Session{Error: "handshake: connection refused"}
			},
			expectedCheck: "OCSP stapling",
		},
		{
			name: "the session ticket could not be read",
			mutate: func(result *observation.Observation) {
				result.Session.EarlyData = &observation.EarlyData{
					Reason: "the negotiated cipher suite is not one whose records this can open",
				}
			},
			expectedCheck: "0-RTT",
		},
		{
			name: "the ordering probe went unanswered",
			mutate: func(result *observation.Observation) {
				result.Order = &observation.Order{Tested: true, Applicable: true}
			},
			expectedCheck: "cipher suite order",
		},
		{
			name: "the signature hash was never established",
			mutate: func(result *observation.Observation) {
				result.Signature = &observation.Signature{Tested: true}
			},
			expectedCheck: "key exchange hash (SHA-1)",
		},
		{
			// This one is never determined, and must always say so rather than
			// quietly not appearing.
			name:          "client-initiated renegotiation is not testable",
			mutate:        func(result *observation.Observation) {},
			expectedCheck: "client-initiated renegotiation",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			result := cleanObservation()
			result.Session.EarlyData = &observation.EarlyData{Determined: true}

			testCase.mutate(result)

			run, err := AnalyzeConnection(result)
			if err != nil {
				t.Fatalf("analyze connection: %v", err)
			}

			for _, sarifResult := range run.Results {
				if sarifResult.RuleId != rule_id.CheckNotDetermined {
					continue
				}

				check, _ := sarifResult.Properties["check"].(string)
				if check == testCase.expectedCheck {
					if sarifResult.Kind == sarif.KindFail {
						t.Errorf("an undetermined check was reported as a failure")
					}

					return
				}
			}

			t.Errorf("nothing said the %s check was undetermined", testCase.expectedCheck)
		})
	}
}

// SARIF requires a result whose kind is not "fail" to carry level none. A run that
// breaks that is invalid on the wire, and no consumer will say which field did it.
func TestEmittedResultsAreValidSarif(t *testing.T) {
	t.Parallel()

	validLevels := map[sarif.Level]bool{
		sarif.LevelNone:    true,
		sarif.LevelNote:    true,
		sarif.LevelWarning: true,
		sarif.LevelError:   true,
	}

	observations := map[string]*observation.Observation{
		"clean": cleanObservation(),
		"an old server": func() *observation.Observation {
			result := cleanObservation()
			result.Versions[0] = acceptedVersion(wire.VersionSsl30, 0x002f, 0x0005)
			result.Compression.Selected = pointerTo(uint8(1))
			result.Signature.Sha1Accepted = pointerTo(true)
			result.Renegotiation.SecureSupported = pointerTo(false)
			result.Session.OcspStapled = false
			result.Session.EarlyData = &observation.EarlyData{Determined: true, MaxSize: pointerTo(uint32(16384))}

			return result
		}(),
		"nothing determined": {
			Versions: []*observation.Version{acceptedVersion(wire.VersionTls12, 0xc02f)},
			Incomplete: []*observation.Phase{
				{Name: "cipher_suites", Reason: "the connection budget was exhausted"},
			},
		},
	}

	for name, result := range observations {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			run, err := AnalyzeConnection(result)
			if err != nil {
				t.Fatalf("analyze connection: %v", err)
			}

			if run == nil || run.Tool == nil || run.Tool.Driver == nil {
				t.Fatal("no run was produced")
			}

			for _, sarifResult := range run.Results {
				if !validLevels[sarifResult.Level] {
					t.Errorf("rule %q emitted level %q, which SARIF does not define", sarifResult.RuleId, sarifResult.Level)
				}

				if sarifResult.Kind != sarif.KindFail && sarifResult.Level != sarif.LevelNone {
					t.Errorf(
						"rule %q has kind %q with level %q; SARIF requires level none for any kind but fail",
						sarifResult.RuleId,
						sarifResult.Kind,
						sarifResult.Level,
					)
				}

				if sarifResult.Message == nil || strings.TrimSpace(sarifResult.Message.Text) == "" {
					t.Errorf("rule %q emitted no message", sarifResult.RuleId)
				}
			}

			// Every rule raised must be described in the run's own rule table.
			described := map[string]bool{}
			for _, rule := range run.Tool.Driver.Rules {
				described[rule.Id] = true
			}

			for _, sarifResult := range run.Results {
				if !described[sarifResult.RuleId] {
					t.Errorf("rule %q was raised but is not in the rule table", sarifResult.RuleId)
				}
			}
		})
	}
}

func TestAnalyzeConnectionTakesNothing(t *testing.T) {
	t.Parallel()

	run, err := AnalyzeConnection(nil)
	if err != nil {
		t.Fatalf("analyze connection: %v", err)
	}

	if run != nil {
		t.Error("a run was produced from no observation at all")
	}
}
