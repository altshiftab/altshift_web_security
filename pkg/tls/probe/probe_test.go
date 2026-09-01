// These tests stand up deliberately old and weak TLS servers, because that is what
// the checks under test have to find: a version scan that reports TLS 1.0 needs a
// TLS 1.0 server to report it about. The byte conversions are of lengths fixed by
// literals a few lines above each one.
//
//nolint:gosec
package probe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/altshiftab/altshift_web_security/pkg/tls/cipher_suite"
	"github.com/altshiftab/altshift_web_security/pkg/tls/observation"
	"github.com/altshiftab/altshift_web_security/pkg/tls/wire"
)

// newServer starts a TLS server in this process. The probe is a network client, and
// the only honest way to test one is against something that speaks the protocol
// back; crypto/tls is a server whose configuration says exactly what the answers
// should be.
//
// scan that finds TLS 1.0 has to have a TLS 1.0 server to find, and a suite
// enumeration that finds a CBC suite has to be offered one.
//
//nolint:gosec // These servers are deliberately old and deliberately weak: a version
func newServer(t *testing.T, config *tls.Config) *observation.Target {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
	}

	certificateBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("x509 create certificate: %v", err)
	}

	config.Certificates = []tls.Certificate{{Certificate: [][]byte{certificateBytes}, PrivateKey: privateKey}}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", config)
	if err != nil {
		t.Fatalf("tls listen: %v", err)
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			go func() {
				defer func() { _ = conn.Close() }()

				tlsConn, ok := conn.(*tls.Conn)
				if !ok {
					return
				}

				if err := tlsConn.HandshakeContext(context.Background()); err != nil {
					return
				}

				// Read whatever is sent and answer, so a session probe gets far
				// enough for the server to issue a ticket.
				buffer := make([]byte, 1024)
				_ = tlsConn.SetReadDeadline(time.Now().Add(2 * time.Second))

				if _, err := tlsConn.Read(buffer); err == nil {
					_, _ = tlsConn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
				}
			}()
		}
	}()

	t.Cleanup(func() { _ = listener.Close() })

	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatal("the listener has no TCP address")
	}

	return &observation.Target{Host: "127.0.0.1", Port: address.Port, ServerName: "localhost"}
}

// testSettings keep a test's timeouts short: everything is on the loopback, and a
// five-second default would make a failure take a minute to report.
func testSettings() *Settings {
	return &Settings{
		Concurrency:      4,
		ConnectTimeout:   2 * time.Second,
		HandshakeTimeout: 2 * time.Second,
		MaxConnections:   250,
		RetryLimit:       1,
	}
}

func TestProbeVersions(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name         string
		serverConfig *tls.Config
		// expectedAccepted are the versions the server should be found to speak,
		// and expectedRefused the ones it should not.
		expectedAccepted []uint16
		expectedRefused  []uint16
	}{
		{
			name:             "a modern server",
			serverConfig:     &tls.Config{MinVersion: tls.VersionTLS13},
			expectedAccepted: []uint16{wire.VersionTls13},
			expectedRefused:  []uint16{wire.VersionSsl30, wire.VersionTls10, wire.VersionTls11, wire.VersionTls12},
		},
		{
			name:             "tls 1.2 and 1.3",
			serverConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
			expectedAccepted: []uint16{wire.VersionTls12, wire.VersionTls13},
			expectedRefused:  []uint16{wire.VersionSsl30, wire.VersionTls10, wire.VersionTls11},
		},
		{
			// The case a version scan gets wrong by reading the legacy version
			// field: an old server that really does speak the old versions.
			name: "a server that still speaks tls 1.0",
			serverConfig: &tls.Config{
				MinVersion:   tls.VersionTLS10,
				MaxVersion:   tls.VersionTLS12,
				CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			},
			expectedAccepted: []uint16{wire.VersionTls10, wire.VersionTls11, wire.VersionTls12},
			expectedRefused:  []uint16{wire.VersionSsl30, wire.VersionTls13},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			target := newServer(t, testCase.serverConfig)

			result, err := Probe(context.Background(), target, testSettings())
			if err != nil {
				t.Fatalf("probe: %v", err)
			}

			accepted := map[uint16]bool{}
			for _, version := range result.Versions {
				if version != nil && version.Accepted {
					accepted[version.Version] = true
				}
			}

			for _, version := range testCase.expectedAccepted {
				if !accepted[version] {
					t.Errorf("%s was not found to be accepted", wire.VersionName(version))
				}
			}

			for _, version := range testCase.expectedRefused {
				if accepted[version] {
					t.Errorf("%s was found to be accepted, and the server does not speak it", wire.VersionName(version))
				}
			}
		})
	}
}

// The enumeration must find exactly the suites the server was configured with:
// finding fewer means it stopped early, and finding more means it counted a suite
// the server never picked.
func TestProbeEnumeratesCipherSuites(t *testing.T) {
	t.Parallel()

	configured := []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	}

	target := newServer(t, &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
		CipherSuites: configured,
	})

	result, err := Probe(context.Background(), target, testSettings())
	if err != nil {
		t.Fatalf("probe: %v", err)
	}

	var found []uint16
	for _, version := range result.Versions {
		if version != nil && version.Version == wire.VersionTls12 && version.Accepted {
			found = version.CipherSuites

			if !version.CipherSuitesComplete {
				t.Error("the enumeration reported itself incomplete")
			}
		}
	}

	if len(found) != len(configured) {
		t.Fatalf(
			"found %d suites, want %d: %v",
			len(found),
			len(configured),
			suiteNames(found),
		)
	}

	wanted := map[uint16]bool{}
	for _, id := range configured {
		wanted[id] = true
	}

	for _, id := range found {
		if !wanted[id] {
			t.Errorf("%s was found, and the server was not configured with it", cipher_suite.Name(id))
		}
	}
}

// A server with its own preference picks the same suite whichever order it is
// offered them in. Go's server always has one -- PreferServerCipherSuites has been
// ignored since Go 1.17 -- so the other half of the check needs a server that
// follows the client, which newFollowingServer is.
func TestProbeCipherSuiteOrder(t *testing.T) {
	t.Parallel()

	t.Run("the server has its own preference", func(t *testing.T) {
		t.Parallel()

		target := newServer(t, &tls.Config{
			MinVersion: tls.VersionTLS12,
			MaxVersion: tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			},
		})

		result, err := Probe(context.Background(), target, testSettings())
		if err != nil {
			t.Fatalf("probe: %v", err)
		}

		if result.Order == nil || !result.Order.Applicable {
			t.Fatal("the ordering check did not apply")
		}

		if result.Order.ServerEnforces == nil {
			t.Fatal("the ordering check reached no verdict")
		}

		if !*result.Order.ServerEnforces {
			t.Error("the server was found not to enforce an order, and Go's server always does")
		}
	})

	t.Run("the server follows the client", func(t *testing.T) {
		t.Parallel()

		target := newFollowingServer(t)

		result, err := Probe(context.Background(), target, testSettings())
		if err != nil {
			t.Fatalf("probe: %v", err)
		}

		if result.Order == nil || result.Order.ServerEnforces == nil {
			t.Fatal("the ordering check reached no verdict")
		}

		if *result.Order.ServerEnforces {
			t.Error("the server was found to enforce an order, and it takes whatever comes first")
		}
	})
}

// newFollowingServer answers any hello by choosing the first suite it was offered,
// which is what a server with no preference of its own does.
//
// It is a handful of bytes rather than a TLS implementation: a ServerHello naming
// the suite and a ServerHelloDone is everything the probe reads before it drops the
// connection, so everything after it would be code written to be ignored.
func newFollowingServer(t *testing.T) *observation.Target {
	t.Helper()

	listenConfig := &net.ListenConfig{}

	listener, err := listenConfig.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen config listen: %v", err)
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			go func() {
				defer func() { _ = conn.Close() }()

				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

				buffer := make([]byte, 8192)

				read, err := conn.Read(buffer)
				if err != nil {
					return
				}

				suite, ok := firstOfferedSuite(buffer[:read])
				if !ok {
					return
				}

				_, _ = conn.Write(serverHelloRecord(suite))
			}()
		}
	}()

	t.Cleanup(func() { _ = listener.Close() })

	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatal("the listener has no TCP address")
	}

	return &observation.Target{Host: "127.0.0.1", Port: address.Port, ServerName: "localhost"}
}

// firstOfferedSuite reads the first cipher suite out of a ClientHello record.
func firstOfferedSuite(stream []byte) (uint16, bool) {
	records := wire.Reassemble(stream)

	for _, message := range wire.SplitHandshake(records.Handshake) {
		if message.Type != wire.HandshakeTypeClientHello {
			continue
		}

		reader := wire.NewReader(message.Body)

		if _, err := reader.Uint16(); err != nil {
			return 0, false
		}

		if _, err := reader.Bytes(32); err != nil {
			return 0, false
		}

		if _, err := reader.Uint8LengthPrefixed(); err != nil {
			return 0, false
		}

		suites, err := reader.Uint16LengthPrefixed()
		if err != nil {
			return 0, false
		}

		suite, err := suites.Uint16()
		if err != nil {
			return 0, false
		}

		return suite, true
	}

	return 0, false
}

// serverHelloRecord builds a TLS 1.2 ServerHello naming a suite, followed by a
// ServerHelloDone.
func serverHelloRecord(suite uint16) []byte {
	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)
	//nolint:gosec // Both halves of a uint16 are bytes by construction.
	body = append(body, byte(suite>>8), byte(suite))
	body = append(body, 0)

	//nolint:gosec // The body is a fixed 38 bytes, built three lines above.
	handshake := []byte{wire.HandshakeTypeServerHello, 0, 0, byte(len(body))}
	handshake = append(handshake, body...)
	handshake = append(handshake, wire.HandshakeTypeServerHelloDone, 0, 0, 0)

	//nolint:gosec // The handshake is a fixed 46 bytes, built four lines above.
	record := []byte{wire.RecordTypeHandshake, 0x03, 0x03, byte(len(handshake) >> 8), byte(len(handshake))}

	return append(record, handshake...)
}

func TestProbeExtensionsAndCompression(t *testing.T) {
	t.Parallel()

	target := newServer(t, &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12})

	result, err := Probe(context.Background(), target, testSettings())
	if err != nil {
		t.Fatalf("probe: %v", err)
	}

	t.Run("compression is refused", func(t *testing.T) {
		t.Parallel()

		if result.Compression == nil || !result.Compression.Applicable {
			t.Fatal("the compression check did not apply")
		}

		if result.Compression.Selected == nil {
			t.Fatal("the compression check reached no verdict")
		}

		if *result.Compression.Selected != 0 {
			t.Errorf("the server chose compression method %d", *result.Compression.Selected)
		}
	})

	t.Run("extended master secret and secure renegotiation are supported", func(t *testing.T) {
		t.Parallel()

		for _, version := range result.Versions {
			if version == nil || version.Version != wire.VersionTls12 || !version.Accepted {
				continue
			}

			if version.ExtendedMasterSecret == nil || !*version.ExtendedMasterSecret {
				t.Error("extended master secret was not detected, and Go's server does it")
			}

			if version.SecureRenegotiation == nil || !*version.SecureRenegotiation {
				t.Error("secure renegotiation was not detected, and Go's server does it")
			}
		}
	})
}

// Against a TLS 1.3-only server three checks have no subject, and saying so is
// different from saying the server passed them.
func TestProbeAgainstTls13OnlyServer(t *testing.T) {
	t.Parallel()

	target := newServer(t, &tls.Config{MinVersion: tls.VersionTLS13})

	result, err := Probe(context.Background(), target, testSettings())
	if err != nil {
		t.Fatalf("probe: %v", err)
	}

	if result.Compression == nil || result.Compression.Applicable {
		t.Error("compression should not apply to a server that speaks only TLS 1.3")
	}

	if result.Order == nil || result.Order.Applicable {
		t.Error("cipher suite order should not apply to a server that speaks only TLS 1.3")
	}

	// TLS 1.3 removed renegotiation, so this is the one case where the check has
	// an answer rather than an excuse.
	if result.Renegotiation == nil || result.Renegotiation.ClientInitiatedPossible == nil {
		t.Fatal("client-initiated renegotiation should be answerable against a TLS 1.3-only server")
	}

	if *result.Renegotiation.ClientInitiatedPossible {
		t.Error("client-initiated renegotiation was reported possible against TLS 1.3, which forbids it")
	}
}

func TestProbeSession(t *testing.T) {
	t.Parallel()

	target := newServer(t, &tls.Config{MinVersion: tls.VersionTLS13})

	result, err := Probe(context.Background(), target, testSettings())
	if err != nil {
		t.Fatalf("probe: %v", err)
	}

	if result.Session == nil || !result.Session.Established {
		t.Fatalf("no session was established: %v", result.Session)
	}

	if result.Session.Version != tls.VersionTLS13 {
		t.Errorf("session version = %#04x, want TLS 1.3", result.Session.Version)
	}

	// Go's server staples nothing, so this is the negative case.
	if result.Session.OcspStapled {
		t.Error("a stapled OCSP response was reported, and Go's server staples none")
	}

	// Go's server issues tickets but never offers early data over TCP, so the
	// check should reach a verdict of "not offered" rather than fail to reach one.
	if result.Session.EarlyData == nil {
		t.Fatal("the early data check reached no verdict at all")
	}

	if !result.Session.EarlyData.Determined {
		t.Errorf("the early data check was undetermined: %s", result.Session.EarlyData.Reason)
	}

	if result.Session.EarlyData.MaxSize != nil {
		t.Errorf("early data was reported offered at %d bytes, and Go's server offers none", *result.Session.EarlyData.MaxSize)
	}
}

func TestProbeRejectsBadTargets(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		target *observation.Target
	}{
		{name: "no target", target: nil},
		{name: "no host", target: &observation.Target{Port: 443}},
		{
			name:   "nothing listening",
			target: &observation.Target{Host: "127.0.0.1", Port: 1},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			settings := testSettings()
			settings.ConnectTimeout = 200 * time.Millisecond
			settings.HandshakeTimeout = 200 * time.Millisecond
			settings.RetryLimit = 0

			if _, err := Probe(context.Background(), testCase.target, settings); err == nil {
				t.Error("the probe reported success against a target it could not reach")
			}
		})
	}
}

// The budget is what keeps a scan from running away against a server with a long
// suite list. Exhausting it must cut the run short and say so, not report a shorter
// list as though it were the whole answer.
func TestProbeRespectsTheConnectionBudget(t *testing.T) {
	t.Parallel()

	target := newServer(t, &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12})

	settings := testSettings()
	settings.MaxConnections = 3

	result, err := Probe(context.Background(), target, settings)
	if err != nil {
		// Running out before any version was accepted is a legitimate outcome of
		// a budget this small.
		return
	}

	if len(result.Incomplete) == 0 {
		t.Error("the run spent its whole budget and reported nothing incomplete")
	}
}

func suiteNames(ids []uint16) []string {
	names := make([]string, 0, len(ids))
	for _, id := range ids {
		names = append(names, cipher_suite.Name(id))
	}

	return names
}

func TestSettingsDefaults(t *testing.T) {
	t.Parallel()

	settings := DefaultSettings()

	testCases := []struct {
		name  string
		value int
	}{
		{name: "concurrency", value: settings.Concurrency},
		{name: "max connections", value: settings.MaxConnections},
		{name: "connect timeout", value: int(settings.ConnectTimeout)},
		{name: "handshake timeout", value: int(settings.HandshakeTimeout)},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if testCase.value <= 0 {
				t.Errorf("the default %s is %d, which would make every probe fail", testCase.name, testCase.value)
			}
		})
	}

	if _, err := strconv.Atoi("0"); err != nil {
		t.Fatal(err)
	}
}
