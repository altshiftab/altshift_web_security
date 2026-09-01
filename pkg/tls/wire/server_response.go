package wire

import (
	"bytes"
	"fmt"

	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
)

// Alert is what a server says instead of a hello when it will not talk.
type Alert struct {
	Level       uint8
	Description uint8
}

// Fatal reports whether the alert ended the connection. A warning alert does not:
// servers routinely send unrecognized_name for an SNI they do not serve and then
// carry on with the handshake, and treating that as a refusal loses the answer.
func (alert *Alert) Fatal() bool {
	return alert != nil && alert.Level == AlertLevelFatal
}

// Records is the byte stream a server sent, split back into the messages it holds.
//
// A handshake message may span records and several may share one, so the handshake
// bytes are the concatenation of every handshake record's payload, walked
// afterwards. Reading messages record by record works against most servers and
// then fails against the ones that pack differently.
type Records struct {
	Handshake []byte
	Alert     *Alert
	// SawChangeCipherSpec means everything after is encrypted, which for a TLS 1.3
	// server is everything after the ServerHello.
	SawChangeCipherSpec bool
	// Encrypted holds the application-data records, which are handshake messages
	// under TLS 1.3 and cannot be read without the keys.
	Encrypted [][]byte
}

// SplitRecords divides a raw stream into records. A trailing partial record is
// dropped rather than reported: a probe that closes the connection early leaves one
// behind routinely.
func SplitRecords(stream []byte) [][]byte {
	var records [][]byte

	for len(stream) >= 5 {
		length := int(stream[3])<<8 | int(stream[4])
		if len(stream) < 5+length {
			break
		}

		records = append(records, stream[:5+length])
		stream = stream[5+length:]
	}

	return records
}

// Reassemble turns a raw stream into the messages it carries.
func Reassemble(stream []byte) *Records {
	records := &Records{}

	for _, record := range SplitRecords(stream) {
		payload := record[5:]

		switch record[0] {
		case RecordTypeHandshake:
			records.Handshake = append(records.Handshake, payload...)
		case RecordTypeAlert:
			if len(payload) >= 2 && records.Alert == nil {
				records.Alert = &Alert{Level: payload[0], Description: payload[1]}
			}
		case RecordTypeChangeCipherSpec:
			records.SawChangeCipherSpec = true
		case RecordTypeApplicationData:
			records.Encrypted = append(records.Encrypted, record)
		}
	}

	return records
}

// FlightIsComplete reports whether the server has said everything a probe can read,
// so the connection can be dropped rather than held open to a deadline.
//
// There are four ways a flight ends, and only one of them is ServerHelloDone. A
// TLS 1.3 server says everything after its hello under encryption, and a server
// answering with a HelloRetryRequest then waits for a second flight that will never
// come -- both would otherwise cost a full read timeout each, which across the
// hundreds of handshakes a suite enumeration makes is the difference between a scan
// that finishes and one that does not.
func FlightIsComplete(stream []byte) bool {
	records := Reassemble(stream)

	if records.Alert != nil || len(records.Encrypted) != 0 {
		return true
	}

	for _, message := range SplitHandshake(records.Handshake) {
		switch message.Type {
		case HandshakeTypeServerHelloDone:
			return true
		case HandshakeTypeServerHello:
			serverHello, err := ParseServerHello(message.Body)
			if err != nil {
				continue
			}

			if serverHello.IsHelloRetryRequest || serverHello.Version >= VersionTls13 {
				return true
			}
		}
	}

	return false
}

// Message is one handshake message.
type Message struct {
	Type uint8
	Body []byte
}

// SplitHandshake walks the reassembled handshake bytes into messages. A truncated
// trailing message is dropped: a TLS 1.3 flight is cut off mid-stream by design,
// because the probe stops reading once it has what it came for.
func SplitHandshake(handshake []byte) []*Message {
	var messages []*Message

	reader := NewReader(handshake)
	for reader.Len() >= 4 {
		messageType, err := reader.Uint8()
		if err != nil {
			break
		}

		body, err := reader.Uint24LengthPrefixed()
		if err != nil {
			break
		}

		messages = append(messages, &Message{Type: messageType, Body: body.Rest()})
	}

	return messages
}

// ServerHello is what the server chose.
type ServerHello struct {
	// LegacyVersion is the version field of the message, which a TLS 1.3 server
	// pins at TLS 1.2. Version is what was really negotiated.
	LegacyVersion     uint16
	Version           uint16
	Random            []byte
	SessionId         []byte
	CipherSuite       uint16
	CompressionMethod uint8
	Extensions        map[uint16][]byte
	// IsHelloRetryRequest means the server accepted the version and the suite but
	// wants a key share for another group -- which is an answer, not a refusal.
	IsHelloRetryRequest bool
	KeyShareGroup       *uint16
}

// HasExtension reports whether the server sent an extension, which for
// renegotiation_info and extended_master_secret is the entire finding.
func (serverHello *ServerHello) HasExtension(extensionType uint16) bool {
	if serverHello == nil {
		return false
	}

	_, found := serverHello.Extensions[extensionType]

	return found
}

func ParseServerHello(body []byte) (*ServerHello, error) {
	reader := NewReader(body)

	serverHello := &ServerHello{Extensions: map[uint16][]byte{}}

	legacyVersion, err := reader.Uint16()
	if err != nil {
		return nil, fmt.Errorf("uint16 (legacy version): %w", err)
	}
	serverHello.LegacyVersion = legacyVersion
	serverHello.Version = legacyVersion

	random, err := reader.Bytes(32)
	if err != nil {
		return nil, fmt.Errorf("bytes (random): %w", err)
	}
	serverHello.Random = random
	serverHello.IsHelloRetryRequest = bytes.Equal(random, HelloRetryRequestRandom)

	sessionId, err := reader.Uint8LengthPrefixed()
	if err != nil {
		return nil, fmt.Errorf("uint8 length prefixed (session id): %w", err)
	}
	serverHello.SessionId = sessionId.Rest()

	cipherSuite, err := reader.Uint16()
	if err != nil {
		return nil, fmt.Errorf("uint16 (cipher suite): %w", err)
	}
	serverHello.CipherSuite = cipherSuite

	compressionMethod, err := reader.Uint8()
	if err != nil {
		return nil, fmt.Errorf("uint8 (compression method): %w", err)
	}
	serverHello.CompressionMethod = compressionMethod

	// A hello from a server that speaks nothing newer than TLS 1.2 ends here.
	if reader.Empty() {
		return serverHello, nil
	}

	extensions, err := reader.Uint16LengthPrefixed()
	if err != nil {
		return nil, fmt.Errorf("uint16 length prefixed (extensions): %w", err)
	}

	for !extensions.Empty() {
		extensionType, err := extensions.Uint16()
		if err != nil {
			return nil, fmt.Errorf("uint16 (extension type): %w", err)
		}

		data, err := extensions.Uint16LengthPrefixed()
		if err != nil {
			return nil, fmt.Errorf("uint16 length prefixed (extension data): %w", err)
		}

		serverHello.Extensions[extensionType] = data.Rest()
	}

	// The negotiated version lives in supported_versions when it is there. Reading
	// the legacy field instead reports every TLS 1.3 server as TLS 1.2.
	if data, found := serverHello.Extensions[ExtensionSupportedVersions]; found && len(data) >= 2 {
		serverHello.Version = uint16(data[0])<<8 | uint16(data[1])
	}

	if data, found := serverHello.Extensions[ExtensionKeyShare]; found && len(data) >= 2 {
		group := uint16(data[0])<<8 | uint16(data[1])
		serverHello.KeyShareGroup = &group
	}

	return serverHello, nil
}

// ServerKeyExchange carries what the key exchange was done with, which below
// TLS 1.3 is the only place the group and the signing hash are stated in the clear.
type ServerKeyExchange struct {
	// NamedCurve is set for an elliptic curve exchange.
	NamedCurve *uint16
	// PrimeBits and GeneratorIsTwo describe a finite-field exchange.
	PrimeBits      int
	GeneratorIsTwo bool
	// SignatureAlgorithm is present from TLS 1.2 only; below it the hash is
	// implied by the suite and there is no field to read.
	SignatureAlgorithm *uint16
}

// ParseServerKeyExchange reads the message. Whether it describes a curve or a
// finite-field group is decided by the negotiated cipher suite, never by looking at
// the first byte: for an elliptic curve exchange that byte is the curve type, and
// for a finite-field one it is the high byte of the prime's length, which for a
// 768-bit prime is also 3.
func ParseServerKeyExchange(body []byte, version uint16, finiteField bool) (*ServerKeyExchange, error) {
	if len(body) == 0 {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("server key exchange"))
	}

	reader := NewReader(body)
	serverKeyExchange := &ServerKeyExchange{}

	if finiteField {
		prime, err := reader.Uint16LengthPrefixed()
		if err != nil {
			return nil, fmt.Errorf("uint16 length prefixed (dh p): %w", err)
		}

		primeBytes := prime.Rest()
		serverKeyExchange.PrimeBits = significantBits(primeBytes)

		generator, err := reader.Uint16LengthPrefixed()
		if err != nil {
			return nil, fmt.Errorf("uint16 length prefixed (dh g): %w", err)
		}

		generatorBytes := generator.Rest()
		serverKeyExchange.GeneratorIsTwo = len(generatorBytes) == 1 && generatorBytes[0] == 2

		if _, err := reader.Uint16LengthPrefixed(); err != nil {
			return nil, fmt.Errorf("uint16 length prefixed (dh ys): %w", err)
		}
	} else {
		curveType, err := reader.Uint8()
		if err != nil {
			return nil, fmt.Errorf("uint8 (curve type): %w", err)
		}

		// 3 is named_curve. The explicit curve encodings were never deployed and
		// carry no group this can name.
		if curveType != 3 {
			return serverKeyExchange, nil
		}

		namedCurve, err := reader.Uint16()
		if err != nil {
			return nil, fmt.Errorf("uint16 (named curve): %w", err)
		}
		serverKeyExchange.NamedCurve = &namedCurve

		if _, err := reader.Uint8LengthPrefixed(); err != nil {
			return nil, fmt.Errorf("uint8 length prefixed (public point): %w", err)
		}
	}

	if version >= VersionTls12 && reader.Len() >= 2 {
		signatureAlgorithm, err := reader.Uint16()
		if err != nil {
			return nil, fmt.Errorf("uint16 (signature algorithm): %w", err)
		}

		serverKeyExchange.SignatureAlgorithm = &signatureAlgorithm
	}

	return serverKeyExchange, nil
}

// significantBits is the bit length of a big-endian integer, ignoring the leading
// zero bytes an encoder may have left on it.
func significantBits(value []byte) int {
	if len(value) == 0 {
		return 0
	}

	index := 0
	for index < len(value) && value[index] == 0 {
		index++
	}

	if index >= len(value) {
		return 0
	}

	bits := (len(value) - index - 1) * 8
	for leading := value[index]; leading != 0; leading >>= 1 {
		bits++
	}

	return bits
}

// Flight is everything a server said in answer to one hello.
type Flight struct {
	ServerHello        *ServerHello
	ServerKeyExchange  *ServerKeyExchange
	CertificateBytes   []byte
	CertificateStatus  []byte
	HasServerHelloDone bool
	Alert              *Alert
	// Encrypted means the server went encrypted, which under TLS 1.3 is expected
	// and means the rest of the flight cannot be read.
	Encrypted bool
}

// FiniteFieldResolver says whether a negotiated suite does its key exchange over a
// finite field rather than a curve, which is the one thing needed to read a
// ServerKeyExchange and the one thing this package cannot know: the catalogue that
// answers it is built on top of these definitions. A nil resolver reads every
// exchange as elliptic curve.
type FiniteFieldResolver func(cipherSuite uint16) bool

// ParseFlight reads a server's answer.
func ParseFlight(stream []byte, finiteField FiniteFieldResolver) (*Flight, error) {
	records := Reassemble(stream)

	flight := &Flight{Alert: records.Alert, Encrypted: len(records.Encrypted) != 0}

	messages := SplitHandshake(records.Handshake)
	if len(messages) == 0 {
		if records.Alert != nil {
			return flight, nil
		}

		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: no handshake message was received", altshiftErrors.ErrParseError),
			len(stream),
		)
	}

	for _, message := range messages {
		switch message.Type {
		case HandshakeTypeServerHello:
			serverHello, err := ParseServerHello(message.Body)
			if err != nil {
				return nil, fmt.Errorf("parse server hello: %w", err)
			}

			flight.ServerHello = serverHello
		case HandshakeTypeCertificate:
			flight.CertificateBytes = message.Body
		case HandshakeTypeCertificateStatus:
			flight.CertificateStatus = message.Body
		case HandshakeTypeServerKeyExchange:
			if flight.ServerHello == nil {
				continue
			}

			isFiniteField := finiteField != nil && finiteField(flight.ServerHello.CipherSuite)

			serverKeyExchange, err := ParseServerKeyExchange(
				message.Body,
				flight.ServerHello.Version,
				isFiniteField,
			)
			if err != nil {
				return nil, fmt.Errorf("parse server key exchange: %w", err)
			}

			flight.ServerKeyExchange = serverKeyExchange
		case HandshakeTypeServerHelloDone:
			flight.HasServerHelloDone = true
		}
	}

	return flight, nil
}
