// These tests stand up deliberately old TLS servers, because a hello built for
// TLS 1.0 needs a TLS 1.0 server to be answered by. The byte conversions are of
// lengths fixed by literals a few lines above each one.
//
//nolint:gosec
package wire

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"net"
	"testing"
	"time"
)

// newServer starts an in-process TLS server, which is what makes the encoder
// testable: a hello these tests build has to be one crypto/tls will answer, and
// nothing short of a real server proves that.
//
// to have a TLS 1.0 server to be answered by.
//
//nolint:gosec // These servers are deliberately old: a hello built for TLS 1.0 has
func newServer(t *testing.T, config *tls.Config) net.Listener {
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

				if tlsConn, ok := conn.(*tls.Conn); ok {
					_ = tlsConn.HandshakeContext(context.Background())
				}
			}()
		}
	}()

	t.Cleanup(func() { _ = listener.Close() })

	return listener
}

// exchange writes a hello and reads whatever the server says back, stopping at the
// end of the server's first flight.
func exchange(t *testing.T, address string, clientHello *ClientHello) []byte {
	t.Helper()

	marshalled, err := clientHello.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	dialer := &net.Dialer{Timeout: 5 * time.Second}

	conn, err := dialer.DialContext(context.Background(), "tcp", address)
	if err != nil {
		t.Fatalf("dialer dial context: %v", err)
	}
	defer func() { _ = conn.Close() }()

	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	if _, err := conn.Write(marshalled); err != nil {
		t.Fatalf("write: %v", err)
	}

	var stream []byte
	buffer := make([]byte, 4096)

	for {
		read, err := conn.Read(buffer)
		if read > 0 {
			stream = append(stream, buffer[:read]...)
		}

		if err != nil || FlightIsComplete(stream) {
			break
		}
	}

	return stream
}

func TestClientHelloIsAnsweredByCryptoTls(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name         string
		serverConfig *tls.Config
		clientHello  *ClientHello
		// expectedVersion is what the server should negotiate.
		expectedVersion uint16
		// expectedSuite, when non-zero, is the suite it should pick.
		expectedSuite uint16
		// expectHelloRetryRequest means the hello deliberately offered no usable
		// key share.
		expectHelloRetryRequest bool
	}{
		{
			name:         "tls 1.2",
			serverConfig: &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12},
			clientHello: &ClientHello{
				LegacyVersion:        VersionTls12,
				ServerName:           "localhost",
				CipherSuites:         []uint16{0xc02b, 0xc02c, 0xc009, 0xc00a},
				SupportedGroups:      DefaultSupportedGroups,
				SignatureAlgorithms:  DefaultSignatureAlgorithms,
				EcPointFormats:       true,
				RenegotiationInfo:    true,
				ExtendedMasterSecret: true,
			},
			expectedVersion: VersionTls12,
			expectedSuite:   0xc02b,
		},
		{
			name:         "tls 1.3",
			serverConfig: &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13},
			clientHello: &ClientHello{
				LegacyVersion:       VersionTls12,
				ServerName:          "localhost",
				CipherSuites:        []uint16{0x1301, 0x1302, 0x1303},
				SupportedGroups:     []uint16{GroupX25519, GroupSecp256r1},
				SignatureAlgorithms: DefaultSignatureAlgorithms,
				SupportedVersions:   []uint16{VersionTls13},
				KeyShareGroup:       GroupX25519,
				EcPointFormats:      true,
			},
			expectedVersion: VersionTls13,
			expectedSuite:   0x1301,
		},
		{
			name:         "tls 1.0",
			serverConfig: &tls.Config{MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS10},
			clientHello: &ClientHello{
				LegacyVersion:       VersionTls10,
				ServerName:          "localhost",
				CipherSuites:        []uint16{0xc009, 0xc00a},
				SupportedGroups:     DefaultSupportedGroups,
				SignatureAlgorithms: DefaultSignatureAlgorithms,
				EcPointFormats:      true,
			},
			expectedVersion: VersionTls10,
			expectedSuite:   0xc009,
		},
		{
			// A key share for a group the server will not use is answered with a
			// HelloRetryRequest naming the group it wants. That is an answer: the
			// version and the suite were both accepted.
			name:         "a key share the server will not take",
			serverConfig: &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13},
			clientHello: &ClientHello{
				LegacyVersion:       VersionTls12,
				ServerName:          "localhost",
				CipherSuites:        []uint16{0x1301, 0x1302, 0x1303},
				SupportedGroups:     []uint16{GroupSecp384r1},
				SignatureAlgorithms: DefaultSignatureAlgorithms,
				SupportedVersions:   []uint16{VersionTls13},
				KeyShareGroup:       0,
			},
			expectedVersion:         VersionTls13,
			expectHelloRetryRequest: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			listener := newServer(t, testCase.serverConfig)

			flight, err := ParseFlight(exchange(t, listener.Addr().String(), testCase.clientHello), nil)
			if err != nil {
				t.Fatalf("parse flight: %v", err)
			}

			if flight.Alert.Fatal() {
				t.Fatalf("the server sent a fatal alert, description %d", flight.Alert.Description)
			}

			if flight.ServerHello == nil {
				t.Fatal("no server hello was parsed")
			}

			if flight.ServerHello.Version != testCase.expectedVersion {
				t.Errorf(
					"negotiated version = %#04x, want %#04x",
					flight.ServerHello.Version,
					testCase.expectedVersion,
				)
			}

			if testCase.expectedSuite != 0 && flight.ServerHello.CipherSuite != testCase.expectedSuite {
				t.Errorf(
					"cipher suite = %#04x, want %#04x",
					flight.ServerHello.CipherSuite,
					testCase.expectedSuite,
				)
			}

			if flight.ServerHello.IsHelloRetryRequest != testCase.expectHelloRetryRequest {
				t.Errorf(
					"hello retry request = %v, want %v",
					flight.ServerHello.IsHelloRetryRequest,
					testCase.expectHelloRetryRequest,
				)
			}
		})
	}
}

// A TLS 1.2 server states whether it will do extended master secret and secure
// renegotiation by echoing the extensions, and that echo is the whole of both
// checks. Go's server does both, so their absence here would be the parser's fault.
func TestServerHelloExtensionsAreRead(t *testing.T) {
	t.Parallel()

	listener := newServer(t, &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12})

	clientHello := &ClientHello{
		LegacyVersion:        VersionTls12,
		ServerName:           "localhost",
		CipherSuites:         []uint16{0xc02b, 0xc02c},
		SupportedGroups:      DefaultSupportedGroups,
		SignatureAlgorithms:  DefaultSignatureAlgorithms,
		EcPointFormats:       true,
		RenegotiationInfo:    true,
		ExtendedMasterSecret: true,
	}

	flight, err := ParseFlight(exchange(t, listener.Addr().String(), clientHello), nil)
	if err != nil {
		t.Fatalf("parse flight: %v", err)
	}

	testCases := []struct {
		name          string
		extensionType uint16
	}{
		{name: "extended master secret", extensionType: ExtensionExtendedMasterSecret},
		{name: "renegotiation info", extensionType: ExtensionRenegotiationInfo},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if !flight.ServerHello.HasExtension(testCase.extensionType) {
				t.Errorf("the server hello does not carry the %s extension", testCase.name)
			}
		})
	}

	// The elliptic curve exchange states its group in the clear, below TLS 1.3.
	if flight.ServerKeyExchange == nil {
		t.Fatal("no server key exchange was parsed")
	}

	if flight.ServerKeyExchange.NamedCurve == nil {
		t.Fatal("the server key exchange names no curve")
	}

	if flight.ServerKeyExchange.SignatureAlgorithm == nil {
		t.Error("the server key exchange carries no signature algorithm, which TLS 1.2 requires")
	}
}

func TestClientHelloMarshal(t *testing.T) {
	t.Parallel()

	clientHello := &ClientHello{
		LegacyVersion: VersionTls12,
		Random:        bytes.Repeat([]byte{0xAA}, 32),
		SessionId:     []byte{},
		CipherSuites:  []uint16{0x1301, 0x00ff},
	}

	marshalled, err := clientHello.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	expected := []byte{
		0x16, 0x03, 0x01, 0x00, 0x31, // record: handshake, TLS 1.0, 49 bytes
		0x01, 0x00, 0x00, 0x2d, // ClientHello, 45 bytes
		0x03, 0x03, // legacy_version TLS 1.2
	}
	expected = append(expected, bytes.Repeat([]byte{0xAA}, 32)...)
	expected = append(expected,
		0x00,                               // empty session id
		0x00, 0x04, 0x13, 0x01, 0x00, 0xff, // two cipher suites
		0x01, 0x00, // one compression method, null
		0x00, 0x00, // no extensions
	)

	if !bytes.Equal(marshalled, expected) {
		t.Errorf("marshal =\n%x\nwant\n%x", marshalled, expected)
	}
}

// The record version is TLS 1.0 whatever the hello negotiates, and a hello that
// would land in the 256..511 range is padded past it.
func TestClientHelloRecordShape(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		clientHello *ClientHello
		// expectPadded means the record must not land in the awkward range.
		expectPadded bool
	}{
		{
			name: "a small hello is left alone",
			clientHello: &ClientHello{
				LegacyVersion: VersionTls12,
				CipherSuites:  []uint16{0x1301},
			},
		},
		{
			name: "a hello in the awkward range is padded past it",
			clientHello: &ClientHello{
				LegacyVersion: VersionTls12,
				ServerName:    "localhost",
				// Enough suites to land the record between 256 and 511 bytes.
				CipherSuites:        make([]uint16, 60),
				SignatureAlgorithms: DefaultSignatureAlgorithms,
			},
			expectPadded: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			marshalled, err := testCase.clientHello.Marshal()
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}

			if marshalled[1] != 0x03 || marshalled[2] != 0x01 {
				t.Errorf("record version = %#02x%02x, want 0x0301", marshalled[1], marshalled[2])
			}

			if length := int(binary.BigEndian.Uint16(marshalled[3:5])); length+5 != len(marshalled) {
				t.Errorf("record length field = %d, but the record is %d bytes", length, len(marshalled)-5)
			}

			if testCase.expectPadded && len(marshalled) >= 256 && len(marshalled) < 512 {
				t.Errorf("the record is %d bytes, inside the range that gets dropped", len(marshalled))
			}
		})
	}
}

func TestReader(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		// read is what the case does with a reader over data.
		read func(*Reader) error
		data []byte
		// expectError says the read should be refused rather than run off the end.
		expectError bool
	}{
		{
			name: "uint16 within bounds",
			data: []byte{0x12, 0x34},
			read: func(reader *Reader) error { _, err := reader.Uint16(); return err },
		},
		{
			name:        "uint16 past the end",
			data:        []byte{0x12},
			read:        func(reader *Reader) error { _, err := reader.Uint16(); return err },
			expectError: true,
		},
		{
			name:        "uint24 past the end",
			data:        []byte{0x00, 0x01},
			read:        func(reader *Reader) error { _, err := reader.Uint24(); return err },
			expectError: true,
		},
		{
			name: "a length prefix that fits",
			data: []byte{0x02, 0xAA, 0xBB},
			read: func(reader *Reader) error { _, err := reader.Uint8LengthPrefixed(); return err },
		},
		{
			name:        "a length prefix that claims more than there is",
			data:        []byte{0x05, 0xAA},
			read:        func(reader *Reader) error { _, err := reader.Uint8LengthPrefixed(); return err },
			expectError: true,
		},
		{
			name:        "a uint16 list of odd length",
			data:        []byte{0x00, 0x01, 0x02},
			read:        func(reader *Reader) error { _, err := reader.Uint16List(); return err },
			expectError: true,
		},
		{
			name:        "bytes past the end",
			data:        []byte{0xAA},
			read:        func(reader *Reader) error { _, err := reader.Bytes(4); return err },
			expectError: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			err := testCase.read(NewReader(testCase.data))

			if testCase.expectError && err == nil {
				t.Error("the read was allowed past the end of the data")
			}

			if !testCase.expectError && err != nil {
				t.Errorf("read error = %v", err)
			}
		})
	}
}

// A sub-reader is bounded by its length prefix, so what follows the block cannot be
// read out of it by mistake. This is the property the whole parser leans on.
func TestReaderSubReaderIsBounded(t *testing.T) {
	t.Parallel()

	reader := NewReader([]byte{0x02, 0xAA, 0xBB, 0xCC, 0xDD})

	inner, err := reader.Uint8LengthPrefixed()
	if err != nil {
		t.Fatalf("uint8 length prefixed: %v", err)
	}

	if got := inner.Rest(); !bytes.Equal(got, []byte{0xAA, 0xBB}) {
		t.Errorf("inner = %x, want aabb", got)
	}

	if got := reader.Rest(); !bytes.Equal(got, []byte{0xCC, 0xDD}) {
		t.Errorf("outer = %x, want ccdd", got)
	}
}

func TestSplitRecordsAndHandshake(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		stream []byte
		// expectedTypes are the handshake message types the stream carries.
		expectedTypes []uint8
		expectedAlert *Alert
	}{
		{
			name: "two messages in one record",
			stream: append(
				[]byte{0x16, 0x03, 0x03, 0x00, 0x08},
				0x0e, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00,
			),
			expectedTypes: []uint8{HandshakeTypeServerHelloDone, HandshakeTypeServerHelloDone},
		},
		{
			// One message split across two records is the case that breaks a
			// parser which reads messages record by record.
			name: "one message across two records",
			stream: append(
				append([]byte{0x16, 0x03, 0x03, 0x00, 0x03}, 0x0b, 0x00, 0x00),
				append([]byte{0x16, 0x03, 0x03, 0x00, 0x03}, 0x02, 0xAA, 0xBB)...,
			),
			expectedTypes: []uint8{HandshakeTypeCertificate},
		},
		{
			name:          "a fatal alert",
			stream:        []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28},
			expectedAlert: &Alert{Level: AlertLevelFatal, Description: AlertHandshakeFailure},
		},
		{
			name:   "a truncated trailing record is dropped",
			stream: []byte{0x16, 0x03, 0x03, 0x00, 0x10, 0x0e},
		},
		{name: "nothing at all", stream: nil},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			records := Reassemble(testCase.stream)

			var gotTypes []uint8
			for _, message := range SplitHandshake(records.Handshake) {
				gotTypes = append(gotTypes, message.Type)
			}

			if len(gotTypes) != len(testCase.expectedTypes) {
				t.Fatalf("message types = %v, want %v", gotTypes, testCase.expectedTypes)
			}

			for index, expected := range testCase.expectedTypes {
				if gotTypes[index] != expected {
					t.Errorf("message %d type = %d, want %d", index, gotTypes[index], expected)
				}
			}

			if testCase.expectedAlert == nil {
				if records.Alert != nil {
					t.Errorf("alert = %v, want none", records.Alert)
				}

				return
			}

			if records.Alert == nil {
				t.Fatal("no alert was read")
			}

			if *records.Alert != *testCase.expectedAlert {
				t.Errorf("alert = %v, want %v", records.Alert, testCase.expectedAlert)
			}
		})
	}
}

func TestParseServerKeyExchange(t *testing.T) {
	t.Parallel()

	// A finite-field message whose prime is 2048 bits and whose generator is 2.
	finiteFieldBody := func() []byte {
		var body []byte
		prime := make([]byte, 256)
		prime[0] = 0xFF

		body = binary.BigEndian.AppendUint16(body, uint16(len(prime)))
		body = append(body, prime...)
		body = binary.BigEndian.AppendUint16(body, 1)
		body = append(body, 2)
		body = binary.BigEndian.AppendUint16(body, 4)
		body = append(body, 0xDE, 0xAD, 0xBE, 0xEF)
		body = binary.BigEndian.AppendUint16(body, 0x0401)

		return body
	}()

	testCases := []struct {
		name        string
		body        []byte
		version     uint16
		finiteField bool
		// expectedCurve, expectedPrimeBits and expectedSignature are what the
		// message should be read as.
		expectedCurve     *uint16
		expectedPrimeBits int
		expectedGenerator bool
		expectedSignature *uint16
		expectError       bool
	}{
		{
			name:              "elliptic curve, tls 1.2",
			body:              []byte{3, 0x00, 0x1d, 0x01, 0xAA, 0x04, 0x03, 0x00, 0x47},
			version:           VersionTls12,
			expectedCurve:     pointerTo(GroupX25519),
			expectedSignature: pointerTo(uint16(0x0403)),
		},
		{
			// Below TLS 1.2 there is no signature algorithm field; reading one
			// would take the first two bytes of the signature instead.
			name:          "elliptic curve, tls 1.0",
			body:          []byte{3, 0x00, 0x1d, 0x01, 0xAA, 0x00, 0x47},
			version:       VersionTls10,
			expectedCurve: pointerTo(GroupX25519),
		},
		{
			name:              "finite field",
			body:              finiteFieldBody,
			version:           VersionTls12,
			finiteField:       true,
			expectedPrimeBits: 2048,
			expectedGenerator: true,
			expectedSignature: pointerTo(uint16(0x0401)),
		},
		{name: "empty", body: nil, version: VersionTls12, expectError: true},
		{name: "truncated", body: []byte{3, 0x00}, version: VersionTls12, expectError: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			serverKeyExchange, err := ParseServerKeyExchange(testCase.body, testCase.version, testCase.finiteField)

			if testCase.expectError {
				if err == nil {
					t.Fatal("the message was accepted, and should not have been")
				}

				return
			}

			if err != nil {
				t.Fatalf("parse server key exchange: %v", err)
			}

			switch {
			case testCase.expectedCurve == nil && serverKeyExchange.NamedCurve != nil:
				t.Errorf("named curve = %d, want none", *serverKeyExchange.NamedCurve)
			case testCase.expectedCurve != nil && serverKeyExchange.NamedCurve == nil:
				t.Error("no named curve was read")
			case testCase.expectedCurve != nil && *serverKeyExchange.NamedCurve != *testCase.expectedCurve:
				t.Errorf("named curve = %d, want %d", *serverKeyExchange.NamedCurve, *testCase.expectedCurve)
			}

			if serverKeyExchange.PrimeBits != testCase.expectedPrimeBits {
				t.Errorf("prime bits = %d, want %d", serverKeyExchange.PrimeBits, testCase.expectedPrimeBits)
			}

			if serverKeyExchange.GeneratorIsTwo != testCase.expectedGenerator {
				t.Errorf("generator is two = %v, want %v", serverKeyExchange.GeneratorIsTwo, testCase.expectedGenerator)
			}

			switch {
			case testCase.expectedSignature == nil && serverKeyExchange.SignatureAlgorithm != nil:
				t.Errorf("signature algorithm = %#04x, want none", *serverKeyExchange.SignatureAlgorithm)
			case testCase.expectedSignature != nil && serverKeyExchange.SignatureAlgorithm == nil:
				t.Error("no signature algorithm was read")
			case testCase.expectedSignature != nil &&
				*serverKeyExchange.SignatureAlgorithm != *testCase.expectedSignature:
				t.Errorf(
					"signature algorithm = %#04x, want %#04x",
					*serverKeyExchange.SignatureAlgorithm,
					*testCase.expectedSignature,
				)
			}
		})
	}
}

func TestSignificantBits(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		value    []byte
		expected int
	}{
		{name: "empty", value: nil, expected: 0},
		{name: "all zero", value: []byte{0x00, 0x00}, expected: 0},
		{name: "one byte", value: []byte{0xFF}, expected: 8},
		{name: "a leading zero byte does not count", value: []byte{0x00, 0xFF}, expected: 8},
		{name: "2048 bits", value: append([]byte{0xFF}, make([]byte, 255)...), expected: 2048},
		{name: "1024 bits", value: append([]byte{0x80}, make([]byte, 127)...), expected: 1024},
		{name: "a short leading byte", value: append([]byte{0x01}, make([]byte, 127)...), expected: 1017},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := significantBits(testCase.value); got != testCase.expected {
				t.Errorf("significantBits = %d, want %d", got, testCase.expected)
			}
		})
	}
}

func pointerTo[T any](value T) *T {
	return &value
}
