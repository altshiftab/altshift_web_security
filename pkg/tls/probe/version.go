package probe

import (
	"context"
	"errors"
	"sync"

	"github.com/altshiftab/altshift_web_security/pkg/tls/cipher_suite"
	"github.com/altshiftab/altshift_web_security/pkg/tls/observation"
	"github.com/altshiftab/altshift_web_security/pkg/tls/wire"
)

// probeVersions asks about every version, and enumerates the suites of the ones that
// answer.
//
// The versions run concurrently because they are independent questions; the suite
// enumeration inside one cannot, because each answer decides the next hello.
func (prober *prober) probeVersions(ctx context.Context) []*observation.Version {
	versions := make([]*observation.Version, len(probedVersions))

	concurrency := prober.settings.Concurrency
	if concurrency < 1 {
		concurrency = 1
	}

	semaphore := make(chan struct{}, concurrency)

	var waitGroup sync.WaitGroup

	for index, version := range probedVersions {
		waitGroup.Add(1)

		go func() {
			defer waitGroup.Done()

			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			versions[index] = prober.probeVersion(ctx, version)
		}()
	}

	waitGroup.Wait()

	return versions
}

func (prober *prober) probeVersion(ctx context.Context, version uint16) *observation.Version {
	result := &observation.Version{Version: version, Attempted: true}

	suites := cipher_suite.ForVersion(version)
	if len(suites) == 0 {
		result.Attempted = false

		return result
	}

	flight, err := prober.handshakeWithRetry(ctx, prober.baseHello(version, suites))
	if err != nil {
		if errors.Is(err, errBudgetExhausted) {
			result.Attempted = false
			prober.noteIncomplete("versions", "the connection budget was exhausted")

			return result
		}

		result.TransportError = err.Error()

		return result
	}

	if flight.Alert.Fatal() {
		description := flight.Alert.Description
		result.AlertDescription = &description

		return result
	}

	serverHello := flight.ServerHello
	if serverHello == nil {
		return result
	}

	// A server that answers a 1.0 hello by negotiating 1.2 has not accepted 1.0.
	// This is the check that keeps a modern server from being reported as
	// speaking every version it was asked about.
	if serverHello.Version != version {
		return result
	}

	result.Accepted = true

	readServerHello(result, serverHello, flight)

	suites, complete := prober.enumerate(ctx, version, serverHello.CipherSuite)
	result.CipherSuites = suites
	result.CipherSuitesComplete = complete

	return result
}

// readServerHello takes everything a single hello settles: the group, the extension
// echoes, and the key exchange parameters.
func readServerHello(result *observation.Version, serverHello *wire.ServerHello, flight *wire.Flight) {
	if serverHello.Version >= wire.VersionTls13 {
		// TLS 1.3 has no extended master secret and no renegotiation to secure:
		// both are built in, so there is nothing to report either way.
		if serverHello.KeyShareGroup != nil {
			group := *serverHello.KeyShareGroup
			result.SelectedGroup = &group
		}

		return
	}

	extendedMasterSecret := serverHello.HasExtension(wire.ExtensionExtendedMasterSecret)
	result.ExtendedMasterSecret = &extendedMasterSecret

	secureRenegotiation := serverHello.HasExtension(wire.ExtensionRenegotiationInfo)
	result.SecureRenegotiation = &secureRenegotiation

	serverKeyExchange := flight.ServerKeyExchange
	if serverKeyExchange == nil {
		return
	}

	if serverKeyExchange.NamedCurve != nil {
		group := *serverKeyExchange.NamedCurve
		result.SelectedGroup = &group
	}

	if serverKeyExchange.PrimeBits != 0 {
		result.FiniteField = &observation.FiniteField{
			PrimeBits:      serverKeyExchange.PrimeBits,
			GeneratorIsTwo: serverKeyExchange.GeneratorIsTwo,
		}
	}

	if serverKeyExchange.SignatureAlgorithm != nil {
		signatureAlgorithm := *serverKeyExchange.SignatureAlgorithm
		result.SignatureAlgorithm = &signatureAlgorithm
	}
}

// enumerate finds every suite a server will accept at a version, by offering all of
// them, removing what it picks and asking again until it picks nothing.
//
// The order of the result is the server's own preference when it has one: each round
// it chooses its favourite of what remains. When it has none it takes the first of
// what it was offered, and the order is this catalogue's -- which is why the
// ordering check is a separate question and not read off this list.
//
// The first pick is passed in rather than asked for again: the version probe has
// already made that handshake.
func (prober *prober) enumerate(
	ctx context.Context,
	version uint16,
	firstPick uint16,
) ([]uint16, bool) {
	remaining := make([]uint16, 0, len(cipher_suite.ForVersion(version)))
	for _, id := range cipher_suite.ForVersion(version) {
		if id != firstPick {
			remaining = append(remaining, id)
		}
	}

	accepted := []uint16{firstPick}

	for len(remaining) != 0 {
		flight, err := prober.handshakeWithRetry(ctx, prober.baseHello(version, remaining))
		if err != nil {
			if errors.Is(err, errBudgetExhausted) {
				prober.noteIncomplete(
					"cipher_suites",
					"the connection budget was exhausted before every suite had been offered",
				)
			} else {
				prober.noteIncomplete(
					"cipher_suites",
					"the server stopped answering before every suite had been offered",
				)
			}

			return accepted, false
		}

		// A refusal is the ordinary way this ends: the server will take none of
		// what is left.
		if flight.Alert.Fatal() || flight.ServerHello == nil {
			return accepted, true
		}

		picked := flight.ServerHello.CipherSuite

		// A server that picks something it was not offered, or picks the same
		// thing twice, would loop forever. Neither is legal, and both happen.
		index := indexOf(remaining, picked)
		if index < 0 {
			prober.noteIncomplete("cipher_suites", "the server chose a suite it was not offered")

			return accepted, false
		}

		accepted = append(accepted, picked)
		remaining = append(remaining[:index], remaining[index+1:]...)
	}

	return accepted, true
}

func indexOf(values []uint16, wanted uint16) int {
	for index, value := range values {
		if value == wanted {
			return index
		}
	}

	return -1
}
