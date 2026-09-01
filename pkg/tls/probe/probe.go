// Package probe asks a server what it will do, one aborted handshake at a time.
//
// Nothing here completes a handshake or derives a key, with the single exception of
// the session leg, which needs a finished connection to see a stapled OCSP response
// and a session ticket. Everything else is a ClientHello written to a socket and a
// ServerHello read back: what a server will negotiate is decided by then, and going
// further would mean implementing a record layer to learn nothing more.
//
// The cost is connections. Finding which suites a server accepts means offering all
// of them, noting the one it picks, removing it and asking again -- so the number of
// handshakes is the number of suites the server accepts, plus one, per version. The
// settings bound that, and a run that hits the bound records which phase it cut
// short rather than reporting a shorter list as though it were the whole answer.
package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/altshiftab/altshift_web_security/pkg/tls/cipher_suite"
	"github.com/altshiftab/altshift_web_security/pkg/tls/observation"
	"github.com/altshiftab/altshift_web_security/pkg/tls/wire"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
)

// Settings bound a run.
type Settings struct {
	// Concurrency is how many handshakes may be in flight at once. The suite
	// enumeration within a version is sequential by nature -- each answer decides
	// the next question -- so this parallelises across versions.
	Concurrency int
	// ConnectTimeout and HandshakeTimeout bound one attempt.
	ConnectTimeout   time.Duration
	HandshakeTimeout time.Duration
	// MaxConnections is the whole run's budget. A server with a long suite list
	// costs more than one with a short list, and a run that would cost more than
	// this stops and says so.
	MaxConnections int
	// RetryLimit is how many times a failed connection is tried again before the
	// phase it belongs to is abandoned.
	RetryLimit int
	// ServerName is what to send as SNI. Empty sends the host.
	ServerName string
}

// DefaultSettings are what a caller gets for not choosing. The connection budget is
// set for an ordinary server: five versions, of which at most two are usually
// accepted, and a few dozen suites between them.
func DefaultSettings() *Settings {
	return &Settings{
		Concurrency:      4,
		ConnectTimeout:   5 * time.Second,
		HandshakeTimeout: 5 * time.Second,
		MaxConnections:   250,
		RetryLimit:       2,
	}
}

var (
	// errBudgetExhausted ends a phase because the run has spent its connections.
	// It is not a failure of the server, and never reaches a caller.
	errBudgetExhausted = errors.New("the connection budget is exhausted")

	// ErrNotTlsServer is what a caller gets when nothing at the address would
	// speak TLS at any version. It is the one outcome that is the caller's
	// problem rather than a finding about the server.
	ErrNotTlsServer = errors.New("no tls version was accepted")

	// errNoAnswer is a connection that opened and then closed without a word.
	errNoAnswer = errors.New("the server closed the connection without answering")

	// errNoAttempt guards against a retry limit that leaves no attempt to make.
	errNoAttempt = errors.New("the retry limit left no attempt to make")

	// errCancelled ends a run whose context is done but which has no cause to give.
	errCancelled = errors.New("the run was cancelled")
)

// probedVersions are the versions asked about, oldest first.
//
// SSL 2.0 is absent: its hello is a different format that nothing here speaks, and
// a server still serving it in 2026 would have to be reached through a probe worth
// more than the finding. SSL 3.0 is present because its hello is the same shape as
// every later one.
var probedVersions = []uint16{
	wire.VersionSsl30,
	wire.VersionTls10,
	wire.VersionTls11,
	wire.VersionTls12,
	wire.VersionTls13,
}

type prober struct {
	address    string
	serverName string
	settings   *Settings

	// spent counts connections against the budget.
	spent atomic.Int64

	// incomplete collects the phases that were cut short.
	incompleteMutex sync.Mutex
	incomplete      []*observation.Phase
}

// Probe asks a server everything the checks need to know.
//
// It returns an error only when the target is not a TLS server at all -- when no
// version was accepted and nothing answered. A server that refuses most of what it
// is offered is not an error; it is the finding.
func Probe(ctx context.Context, target *observation.Target, settings *Settings) (*observation.Observation, error) {
	if target == nil {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("target"))
	}

	if target.Host == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("host"))
	}

	if settings == nil {
		settings = DefaultSettings()
	}

	port := target.Port
	if port == 0 {
		port = 443
	}

	serverName := target.ServerName
	if serverName == "" {
		serverName = target.Host
	}

	prober := &prober{
		address:    net.JoinHostPort(target.Host, strconv.Itoa(port)),
		serverName: serverName,
		settings:   settings,
	}

	versions := prober.probeVersions(ctx)

	accepted := make([]*observation.Version, 0, len(versions))
	for _, version := range versions {
		if version.Accepted {
			accepted = append(accepted, version)
		}
	}

	if len(accepted) == 0 {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: %s", ErrNotTlsServer, prober.address),
			prober.address,
		)
	}

	result := &observation.Observation{
		Target:   &observation.Target{Host: target.Host, Port: port, ServerName: serverName},
		Versions: versions,
	}

	// Everything below reads what the version scan already established, so the
	// version scan is the one phase that cannot be skipped.
	result.Order = prober.probeOrder(ctx, accepted)
	result.Compression = prober.probeCompression(ctx, accepted)
	result.Groups = prober.probeGroups(ctx, accepted)
	result.Signature = prober.probeSignature(ctx, accepted)
	result.Renegotiation = renegotiationFrom(accepted)
	result.Session = prober.probeSession(ctx)

	result.Incomplete = prober.takeIncomplete()

	return result, nil
}

// bestVersion is the newest version the server accepted, which is what an ordinary
// client would end up speaking and so what the single-connection checks use.
func bestVersion(accepted []*observation.Version) *observation.Version {
	var best *observation.Version

	for _, version := range accepted {
		if best == nil || version.Version > best.Version {
			best = version
		}
	}

	return best
}

// belowTls13 is the newest accepted version that is not TLS 1.3, which is the only
// place compression, renegotiation and extended master secret mean anything.
func belowTls13(accepted []*observation.Version) *observation.Version {
	var best *observation.Version

	for _, version := range accepted {
		if version.Version >= wire.VersionTls13 {
			continue
		}

		if best == nil || version.Version > best.Version {
			best = version
		}
	}

	return best
}

func (prober *prober) noteIncomplete(name string, reason string) {
	prober.incompleteMutex.Lock()
	defer prober.incompleteMutex.Unlock()

	prober.incomplete = append(prober.incomplete, &observation.Phase{Name: name, Reason: reason})
}

func (prober *prober) takeIncomplete() []*observation.Phase {
	prober.incompleteMutex.Lock()
	defer prober.incompleteMutex.Unlock()

	return prober.incomplete
}

// takeConnection claims one against the budget.
func (prober *prober) takeConnection() bool {
	return prober.spent.Add(1) <= int64(prober.settings.MaxConnections)
}

// handshake writes one hello and reads the answer, then drops the connection. The
// handshake is never completed: by the ServerHello the server has said what it will
// negotiate, and finishing would cost a round trip to learn nothing.
func (prober *prober) handshake(ctx context.Context, clientHello *wire.ClientHello) (*wire.Flight, error) {
	if !prober.takeConnection() {
		return nil, errBudgetExhausted
	}

	marshalled, err := clientHello.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}

	dialer := &net.Dialer{Timeout: prober.settings.ConnectTimeout}

	conn, err := dialer.DialContext(ctx, "tcp", prober.address)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("dialer dial context: %w", err), prober.address)
	}
	defer func() { _ = conn.Close() }()

	if err := conn.SetDeadline(time.Now().Add(prober.settings.HandshakeTimeout)); err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("conn set deadline: %w", err))
	}

	if _, err := conn.Write(marshalled); err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("conn write: %w", err), prober.address)
	}

	var stream []byte
	buffer := make([]byte, 4096)

	for {
		read, readErr := conn.Read(buffer)
		if read > 0 {
			stream = append(stream, buffer[:read]...)
		}

		if readErr != nil {
			break
		}

		if wire.FlightIsComplete(stream) {
			break
		}
	}

	if len(stream) == 0 {
		return nil, altshiftErrors.NewWithTrace(errNoAnswer, prober.address)
	}

	flight, err := wire.ParseFlight(stream, isFiniteField)
	if err != nil {
		return nil, fmt.Errorf("parse flight: %w", err)
	}

	return flight, nil
}

// handshakeWithRetry tries again when the connection failed rather than the
// handshake, which is what a rate limiter looks like from here. A fatal alert is an
// answer and is never retried.
func (prober *prober) handshakeWithRetry(ctx context.Context, clientHello *wire.ClientHello) (*wire.Flight, error) {
	var lastErr error

	for attempt := 0; attempt <= prober.settings.RetryLimit; attempt++ {
		if attempt != 0 {
			backoff := time.Duration(attempt) * 250 * time.Millisecond

			select {
			case <-ctx.Done():
				if err := ctx.Err(); err != nil {
					return nil, altshiftErrors.NewWithTrace(fmt.Errorf("context: %w", err))
				}

				return nil, altshiftErrors.NewWithTrace(errCancelled)
			case <-time.After(backoff):
			}
		}

		flight, err := prober.handshake(ctx, clientHello)
		if err == nil {
			if flight == nil {
				return nil, altshiftErrors.NewWithTrace(errNoAnswer, prober.address)
			}

			return flight, nil
		}

		if errors.Is(err, errBudgetExhausted) || errors.Is(err, context.Canceled) {
			return nil, err
		}

		lastErr = err
	}

	// A negative retry limit would leave the loop unrun and nothing to report, and
	// a caller that reads the flight because the error was nil would find nothing
	// there. There is always either a flight or a reason.
	if lastErr == nil {
		lastErr = altshiftErrors.NewWithTrace(errNoAttempt, prober.settings.RetryLimit)
	}

	return nil, lastErr
}

// isFiniteField is the catalogue's answer to how a ServerKeyExchange should be read.
func isFiniteField(cipherSuite uint16) bool {
	return cipher_suite.ById(cipherSuite).FiniteField()
}

// baseHello is the hello every probe starts from: everything an ordinary client
// would send, so that what a server refuses is refused for the reason under test
// rather than because the hello was odd.
func (prober *prober) baseHello(version uint16, cipherSuites []uint16) *wire.ClientHello {
	clientHello := &wire.ClientHello{
		ServerName:          prober.serverName,
		CipherSuites:        cipherSuites,
		SupportedGroups:     wire.DefaultSupportedGroups,
		SignatureAlgorithms: wire.DefaultSignatureAlgorithms,
		EcPointFormats:      true,
		StatusRequest:       true,
	}

	if version >= wire.VersionTls13 {
		// A TLS 1.3 hello pins its legacy version at 1.2 and says what it means
		// in supported_versions.
		clientHello.LegacyVersion = wire.VersionTls12
		clientHello.SupportedVersions = []uint16{wire.VersionTls13}
		clientHello.KeyShareGroup = wire.GroupX25519

		return clientHello
	}

	// Below 1.3 the legacy version is the negotiation, and supported_versions is
	// left out entirely: a 1.3-capable server offered a 1.2 hello must negotiate
	// down, and an old one is not confused by an extension it does not know.
	clientHello.LegacyVersion = version
	clientHello.RenegotiationInfo = true
	clientHello.ExtendedMasterSecret = true

	return clientHello
}
