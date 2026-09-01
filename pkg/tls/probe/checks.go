package probe

import (
	"context"

	"github.com/altshiftab/altshift_web_security/pkg/tls/cipher_suite"
	"github.com/altshiftab/altshift_web_security/pkg/tls/observation"
	"github.com/altshiftab/altshift_web_security/pkg/tls/wire"
)

// probeOrder asks whether the server imposes its own cipher suite preference, by
// offering the same suites twice in opposite orders. A server with a preference
// picks the same suite both times; one without picks whatever came first.
//
// The question only arises below TLS 1.3, where the suites differ in how much they
// are worth. Every TLS 1.3 suite but one is acceptable, and the exception is
// insufficient outright rather than badly ordered.
func (prober *prober) probeOrder(ctx context.Context, accepted []*observation.Version) *observation.Order {
	order := &observation.Order{Tested: true}

	version := belowTls13(accepted)
	if version == nil {
		order.Applicable = false

		return order
	}

	order.Applicable = true

	suites := version.CipherSuites
	if len(suites) < 2 {
		// With one suite there is no order to have.
		enforces := true
		order.ServerEnforces = &enforces

		return order
	}

	forward, err := prober.handshakeWithRetry(ctx, prober.baseHello(version.Version, suites))
	if err != nil || forward == nil || forward.ServerHello == nil {
		prober.noteIncomplete("cipher_suite_order", "the server did not answer the first ordering probe")

		return order
	}

	reversedSuites := reversed(suites)

	backward, err := prober.handshakeWithRetry(ctx, prober.baseHello(version.Version, reversedSuites))
	if err != nil || backward == nil || backward.ServerHello == nil {
		prober.noteIncomplete("cipher_suite_order", "the server did not answer the second ordering probe")

		return order
	}

	enforces := forward.ServerHello.CipherSuite == backward.ServerHello.CipherSuite
	order.ServerEnforces = &enforces

	// The enumeration order is the server's preference only when it has one; when
	// it follows the client, that order is this catalogue's and says nothing about
	// the server.
	if enforces {
		if worse, better := firstOutOfOrder(suites); worse != 0 {
			order.Violation = []uint16{worse, better}
			order.ViolationVersion = version.Version
		}
	}

	return order
}

// firstOutOfOrder finds the first place where the server prefers a suite the policy
// ranks below one it prefers less. Order within a category does not matter; order
// between them does.
func firstOutOfOrder(preference []uint16) (uint16, uint16) {
	for index, current := range preference {
		currentRank := cipher_suite.Categorize(current).Rank()

		for _, later := range preference[index+1:] {
			if cipher_suite.Categorize(later).Rank() < currentRank {
				return current, later
			}
		}
	}

	return 0, 0
}

func reversed(values []uint16) []uint16 {
	out := make([]uint16, len(values))
	for index, value := range values {
		out[len(values)-1-index] = value
	}

	return out
}

// probeCompression offers DEFLATE alongside the null method and sees which comes
// back. A server that compresses records leaks their contents through their length,
// which is CRIME.
//
// It must be asked below TLS 1.3: RFC 8446 requires a 1.3 server to abort when the
// legacy compression list is anything but a single null, so asking a 1.3-only server
// produces an alert that says nothing about compression.
func (prober *prober) probeCompression(
	ctx context.Context,
	accepted []*observation.Version,
) *observation.Compression {
	compression := &observation.Compression{Tested: true}

	version := belowTls13(accepted)
	if version == nil {
		compression.Applicable = false

		return compression
	}

	compression.Applicable = true

	clientHello := prober.baseHello(version.Version, cipher_suite.ForVersion(version.Version))
	// DEFLATE first, null second: a server willing to compress takes the first it
	// recognises, and one that is not still has an acceptable method to choose.
	clientHello.CompressionMethods = []byte{1, 0}

	flight, err := prober.handshakeWithRetry(ctx, clientHello)
	if err != nil || flight == nil || flight.ServerHello == nil {
		prober.noteIncomplete("compression", "the server did not answer the compression probe")

		return compression
	}

	selected := flight.ServerHello.CompressionMethod
	compression.Selected = &selected

	return compression
}

// weakGroups are the groups worth asking about on their own: a server states which
// group it prefers by choosing one, but not which it would stoop to. Offering only
// these answers the second question.
var weakGroups = []uint16{
	// secp224r1, and the finite-field groups, which the 2025 policy is phasing out.
	21,
	wire.GroupFfdhe2048,
	wire.GroupFfdhe3072,
	wire.GroupFfdhe4096,
}

func (prober *prober) probeGroups(ctx context.Context, accepted []*observation.Version) *observation.Groups {
	groups := &observation.Groups{Tested: true, Selected: map[uint16]uint16{}}

	for _, version := range accepted {
		if version.SelectedGroup != nil {
			groups.Selected[version.Version] = *version.SelectedGroup
		}
	}

	version := bestVersion(accepted)
	if version == nil {
		return groups
	}

	clientHello := prober.baseHello(version.Version, cipher_suite.ForVersion(version.Version))
	clientHello.SupportedGroups = weakGroups

	if version.Version >= wire.VersionTls13 {
		// No key share for any of these is generated, so the server answers with a
		// HelloRetryRequest naming the one it wants -- which is the answer.
		clientHello.KeyShareGroup = 0
	}

	flight, err := prober.handshakeWithRetry(ctx, clientHello)
	if err != nil || flight == nil {
		prober.noteIncomplete("key_exchange_parameters", "the server did not answer the weak group probe")

		return groups
	}

	// A refusal is the good answer: the server will not stoop to any of them.
	if flight.Alert.Fatal() || flight.ServerHello == nil {
		return groups
	}

	if group := flight.ServerHello.KeyShareGroup; group != nil {
		groups.WeakAccepted = append(groups.WeakAccepted, *group)

		return groups
	}

	if serverKeyExchange := flight.ServerKeyExchange; serverKeyExchange != nil {
		if serverKeyExchange.NamedCurve != nil {
			groups.WeakAccepted = append(groups.WeakAccepted, *serverKeyExchange.NamedCurve)
		}
	}

	return groups
}

// sha1SignatureAlgorithms and sha224SignatureAlgorithms are offered alone to find
// out whether a server will sign with a hash the policy has retired. A server that
// completes a handshake offering nothing else will use it.
var (
	sha1SignatureAlgorithms   = []uint16{0x0201, 0x0203, 0x0202}
	sha224SignatureAlgorithms = []uint16{0x0301, 0x0303, 0x0302}
)

func (prober *prober) probeSignature(
	ctx context.Context,
	accepted []*observation.Version,
) *observation.Signature {
	signature := &observation.Signature{Tested: true}

	// What the server actually chose, which the version scan already read off the
	// ServerKeyExchange of an ordinary handshake.
	if below := belowTls13(accepted); below != nil && below.SignatureAlgorithm != nil {
		chosen := *below.SignatureAlgorithm
		signature.Chosen = &chosen
	}

	// The question is asked below TLS 1.3, where the answer is a signature sitting
	// in the clear in the ServerKeyExchange.
	//
	// At 1.3 it cannot be asked honestly: the server commits to a signature
	// algorithm in CertificateVerify, which comes after the ServerHello and under
	// encryption, so a server with no acceptable hash still answers the hello and
	// only refuses afterwards. Reading the ServerHello as consent reports every
	// modern server as willing to sign with SHA-1, which is how this check first
	// came out wrong.
	version := belowTls13(accepted)
	if version == nil {
		prober.noteIncomplete(
			"key_exchange_hash",
			"the server accepts only TLS 1.3, where the signature is made after the hello and under encryption",
		)

		return signature
	}

	// Only the forward-secret suites are offered, because they are the ones that
	// sign a ServerKeyExchange. A static RSA handshake signs nothing, so a server
	// that chose one would accept any signature algorithm list at all -- including
	// one holding nothing but SHA-1.
	signingSuites := forwardSecretSuites(version.CipherSuites)
	if len(signingSuites) == 0 {
		prober.noteIncomplete(
			"key_exchange_hash",
			"the server negotiates no forward-secret suite, so no key exchange is signed",
		)

		return signature
	}

	testCases := []struct {
		name                string
		signatureAlgorithms []uint16
		hashes              map[uint16]string
		accepted            **bool
	}{
		{
			name:                "key_exchange_hash_sha1",
			signatureAlgorithms: sha1SignatureAlgorithms,
			hashes:              cipher_suite.BadHashSignatureAlgorithms,
			accepted:            &signature.Sha1Accepted,
		},
		{
			name:                "key_exchange_hash_sha224",
			signatureAlgorithms: sha224SignatureAlgorithms,
			hashes:              cipher_suite.PhaseOutHashSignatureAlgorithms,
			accepted:            &signature.Sha224Accepted,
		},
	}

	for _, testCase := range testCases {
		clientHello := prober.baseHello(version.Version, signingSuites)
		clientHello.SignatureAlgorithms = testCase.signatureAlgorithms

		flight, err := prober.handshakeWithRetry(ctx, clientHello)
		if err != nil || flight == nil {
			prober.noteIncomplete(testCase.name, "the server did not answer the signature algorithm probe")

			continue
		}

		// A refusal is the good answer: the server will not sign with it.
		if flight.Alert.Fatal() || flight.ServerHello == nil {
			will := false
			*testCase.accepted = &will

			continue
		}

		// Anything else has to be proved by the signature the server actually
		// made. A ServerHello alone is not consent.
		serverKeyExchange := flight.ServerKeyExchange
		if serverKeyExchange == nil || serverKeyExchange.SignatureAlgorithm == nil {
			prober.noteIncomplete(testCase.name, "the server signed no key exchange this could read")

			continue
		}

		_, used := testCase.hashes[*serverKeyExchange.SignatureAlgorithm]
		*testCase.accepted = &used
	}

	return signature
}

// forwardSecretSuites are the ones that sign a ServerKeyExchange, which is the only
// place below TLS 1.3 that states which hash the server was willing to use.
func forwardSecretSuites(suites []uint16) []uint16 {
	signing := make([]uint16, 0, len(suites))

	for _, id := range suites {
		if cipher_suite.ById(id).ForwardSecrecy() {
			signing = append(signing, id)
		}
	}

	return signing
}

// renegotiationFrom reads both renegotiation answers out of what the version scan
// already found.
//
// Secure renegotiation is the extension echo. Client-initiated renegotiation is not
// asked at all: injecting a second hello means encrypting it, which means a record
// layer and a key schedule this deliberately does not have. The one case that can be
// answered honestly is a server that speaks only TLS 1.3, where renegotiation was
// removed from the protocol -- so it is not that the check could not be run, it is
// that there is nothing to run it against.
func renegotiationFrom(accepted []*observation.Version) *observation.Renegotiation {
	renegotiation := &observation.Renegotiation{}

	version := belowTls13(accepted)
	if version == nil {
		impossible := false
		renegotiation.ClientInitiatedPossible = &impossible

		return renegotiation
	}

	renegotiation.SecureSupported = version.SecureRenegotiation
	renegotiation.ClientInitiatedReason =
		"testing it needs a completed handshake and an encrypted post-handshake message, " +
			"which needs a TLS record layer this does not implement"

	return renegotiation
}
