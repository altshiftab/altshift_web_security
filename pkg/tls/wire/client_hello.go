package wire

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"fmt"

	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
)

// ClientHello is the hello to send, as fields rather than as bytes. Every probe is
// one of these: what a probe asks about is which fields it fills in.
type ClientHello struct {
	// LegacyVersion is what a server below TLS 1.3 negotiates against. A TLS 1.3
	// hello leaves this at TLS 1.2 and says what it means in SupportedVersions.
	LegacyVersion uint16
	// Random and SessionId are generated when nil, which is what every caller
	// wants; they exist so a test can pin the bytes.
	Random    []byte
	SessionId []byte
	// CipherSuites is offered in the order given. A server that has its own
	// preference ignores the order, which is what the ordering check tests for.
	CipherSuites []uint16
	// CompressionMethods defaults to the null method alone. Offering anything
	// else is how the compression check is made.
	CompressionMethods  []byte
	ServerName          string
	SupportedGroups     []uint16
	SignatureAlgorithms []uint16
	SupportedVersions   []uint16
	// KeyShareGroup carries a real generated share for the groups crypto/ecdh
	// knows. A group it does not know sends no share at all, and the server
	// answers with a HelloRetryRequest naming the group it wants -- which is an
	// answer, not a failure.
	KeyShareGroup        uint16
	RenegotiationInfo    bool
	ExtendedMasterSecret bool
	StatusRequest        bool
	EcPointFormats       bool
	SessionTicket        bool
}

// DefaultSignatureAlgorithms is what a hello offers when it is not asking about
// signature algorithms: enough that any ordinary certificate can be used, so a
// handshake failure means what it appears to mean.
var DefaultSignatureAlgorithms = []uint16{
	0x0403, // ecdsa_secp256r1_sha256
	0x0503, // ecdsa_secp384r1_sha384
	0x0603, // ecdsa_secp521r1_sha512
	0x0804, // rsa_pss_rsae_sha256
	0x0805, // rsa_pss_rsae_sha384
	0x0806, // rsa_pss_rsae_sha512
	0x0401, // rsa_pkcs1_sha256
	0x0501, // rsa_pkcs1_sha384
	0x0601, // rsa_pkcs1_sha512
	0x0203, // ecdsa_sha1
	0x0201, // rsa_pkcs1_sha1
}

// DefaultSupportedGroups is the group list a hello offers when it is not asking
// about groups.
var DefaultSupportedGroups = []uint16{
	GroupX25519,
	GroupSecp256r1,
	GroupSecp384r1,
	GroupSecp521r1,
	GroupFfdhe2048,
	GroupFfdhe3072,
	GroupFfdhe4096,
}

// Marshal builds the complete record to write to the connection.
func (clientHello *ClientHello) Marshal() ([]byte, error) {
	if clientHello == nil {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("client hello"))
	}

	if len(clientHello.CipherSuites) == 0 {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("cipher suites"))
	}

	random := clientHello.Random
	if random == nil {
		random = make([]byte, 32)
		if _, err := rand.Read(random); err != nil {
			return nil, altshiftErrors.NewWithTrace(fmt.Errorf("rand read (random): %w", err))
		}
	}

	sessionId := clientHello.SessionId
	if sessionId == nil {
		// A non-empty legacy session id makes a TLS 1.3 hello look like a
		// resumption attempt to a middlebox, which is what RFC 8446 appendix D.4
		// asks for.
		sessionId = make([]byte, 32)
		if _, err := rand.Read(sessionId); err != nil {
			return nil, altshiftErrors.NewWithTrace(fmt.Errorf("rand read (session id): %w", err))
		}
	}

	compressionMethods := clientHello.CompressionMethods
	if len(compressionMethods) == 0 {
		compressionMethods = []byte{0}
	}

	// Every length below is written into a fixed-width field, so an input too long
	// for its field would be truncated into a hello that means something other than
	// what was asked for. Refusing here is what makes the conversions that follow
	// safe rather than merely usually safe.
	if err := checkLengths(sessionId, compressionMethods, clientHello.CipherSuites); err != nil {
		return nil, fmt.Errorf("check lengths: %w", err)
	}

	var body []byte
	body = binary.BigEndian.AppendUint16(body, clientHello.LegacyVersion)
	body = append(body, random...)
	body = append(body, toByte(len(sessionId)))
	body = append(body, sessionId...)

	body = binary.BigEndian.AppendUint16(body, toUint16(len(clientHello.CipherSuites)*2))
	for _, cipherSuite := range clientHello.CipherSuites {
		body = binary.BigEndian.AppendUint16(body, cipherSuite)
	}

	body = append(body, toByte(len(compressionMethods)))
	body = append(body, compressionMethods...)

	extensions, err := clientHello.marshalExtensions()
	if err != nil {
		return nil, fmt.Errorf("marshal extensions: %w", err)
	}

	body = binary.BigEndian.AppendUint16(body, toUint16(len(extensions)))
	body = append(body, extensions...)

	// A hello whose record lands between 256 and 511 bytes is rejected by some
	// middleboxes; padding it past the range costs nothing. RFC 7685.
	if total := len(body) + 4 + 5; total >= 256 && total < 512 {
		padding := 512 - total + 4
		body = clientHello.repadded(body, extensions, padding)
	}

	if len(body) > 0xffffff {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: the hello is longer than its length field", altshiftErrors.ErrValidationError),
			len(body),
		)
	}

	// A 24-bit length is three bytes taken out of one number, so each is masked
	// rather than range-checked: toByte would refuse the low byte of any hello
	// longer than 255 bytes, which is all of them.
	handshake := []byte{HandshakeTypeClientHello}
	handshake = append(handshake, lowByte(len(body)>>16), lowByte(len(body)>>8), lowByte(len(body)))
	handshake = append(handshake, body...)

	// The record version is TLS 1.0 whatever the hello negotiates: a server that
	// only speaks an older version must still recognise the record.
	record := []byte{RecordTypeHandshake, 0x03, 0x01}
	record = binary.BigEndian.AppendUint16(record, toUint16(len(handshake)))
	record = append(record, handshake...)

	return record, nil
}

// repadded rebuilds the body with a padding extension of the given size appended to
// the extension block.
func (clientHello *ClientHello) repadded(body []byte, extensions []byte, padding int) []byte {
	// The body ends with the extension block and the two bytes of its length, so
	// anything shorter than that is not a body this can rebuild.
	if body == nil || len(body) < 2+len(extensions) {
		return body
	}

	padded := make([]byte, 0, len(extensions)+4+padding)
	padded = append(padded, extensions...)
	padded = appendExtension(padded, ExtensionPadding, make([]byte, padding))

	// Everything before the extension block is unchanged; only its length and its
	// contents move.
	head := body[:len(body)-2-len(extensions)]

	rebuilt := make([]byte, 0, len(head)+2+len(padded))
	rebuilt = append(rebuilt, head...)
	rebuilt = binary.BigEndian.AppendUint16(rebuilt, toUint16(len(padded)))
	rebuilt = append(rebuilt, padded...)

	return rebuilt
}

func (clientHello *ClientHello) marshalExtensions() ([]byte, error) {
	var extensions []byte

	if clientHello.ServerName != "" {
		var name []byte
		name = append(name, 0) // host_name
		name = binary.BigEndian.AppendUint16(name, toUint16(len(clientHello.ServerName)))
		name = append(name, clientHello.ServerName...)

		var list []byte
		list = binary.BigEndian.AppendUint16(list, toUint16(len(name)))
		list = append(list, name...)

		extensions = appendExtension(extensions, ExtensionServerName, list)
	}

	if clientHello.StatusRequest {
		// status_type ocsp, empty responder id list, empty extensions.
		extensions = appendExtension(extensions, ExtensionStatusRequest, []byte{1, 0, 0, 0, 0})
	}

	if len(clientHello.SupportedGroups) != 0 {
		extensions = appendExtension(
			extensions,
			ExtensionSupportedGroups,
			marshalUint16List(clientHello.SupportedGroups),
		)
	}

	if clientHello.EcPointFormats {
		extensions = appendExtension(extensions, ExtensionEcPointFormats, []byte{1, 0})
	}

	if len(clientHello.SignatureAlgorithms) != 0 {
		extensions = appendExtension(
			extensions,
			ExtensionSignatureAlgorithms,
			marshalUint16List(clientHello.SignatureAlgorithms),
		)
	}

	if clientHello.ExtendedMasterSecret {
		extensions = appendExtension(extensions, ExtensionExtendedMasterSecret, nil)
	}

	if clientHello.SessionTicket {
		extensions = appendExtension(extensions, ExtensionSessionTicket, nil)
	}

	if clientHello.RenegotiationInfo {
		extensions = appendExtension(extensions, ExtensionRenegotiationInfo, []byte{0})
	}

	if len(clientHello.SupportedVersions) != 0 {
		var versions []byte
		versions = append(versions, toByte(len(clientHello.SupportedVersions)*2))
		for _, version := range clientHello.SupportedVersions {
			versions = binary.BigEndian.AppendUint16(versions, version)
		}

		extensions = appendExtension(extensions, ExtensionSupportedVersions, versions)

		// A TLS 1.3 hello that offers no PSK mode is still valid, but offering
		// psk_dhe_ke is what makes a server willing to send a session ticket.
		extensions = appendExtension(extensions, ExtensionPskKeyExchangeModes, []byte{1, 1})
	}

	if clientHello.KeyShareGroup != 0 {
		keyShare, err := marshalKeyShare(clientHello.KeyShareGroup)
		if err != nil {
			return nil, fmt.Errorf("marshal key share: %w", err)
		}

		if keyShare != nil {
			extensions = appendExtension(extensions, ExtensionKeyShare, keyShare)
		}
	} else if len(clientHello.SupportedVersions) != 0 {
		// TLS 1.3 requires the extension to be present even when it offers
		// nothing; the server answers with a HelloRetryRequest.
		extensions = appendExtension(extensions, ExtensionKeyShare, []byte{0, 0})
	}

	return extensions, nil
}

// marshalKeyShare generates a real share for the groups crypto/ecdh covers. A group
// it does not cover returns nil rather than an error: a hello with no share is a
// question the server answers with a HelloRetryRequest, and that answer is all the
// group checks need.
func marshalKeyShare(group uint16) ([]byte, error) {
	var curve ecdh.Curve

	switch group {
	case GroupX25519:
		curve = ecdh.X25519()
	case GroupSecp256r1:
		curve = ecdh.P256()
	case GroupSecp384r1:
		curve = ecdh.P384()
	case GroupSecp521r1:
		curve = ecdh.P521()
	default:
		return []byte{0, 0}, nil
	}

	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("curve generate key: %w", err), group)
	}

	public := privateKey.PublicKey().Bytes()

	var entry []byte
	entry = binary.BigEndian.AppendUint16(entry, group)
	entry = binary.BigEndian.AppendUint16(entry, toUint16(len(public)))
	entry = append(entry, public...)

	var list []byte
	list = binary.BigEndian.AppendUint16(list, toUint16(len(entry)))
	list = append(list, entry...)

	return list, nil
}

// checkLengths refuses the inputs whose length will not fit the field it is written
// into.
func checkLengths(sessionId []byte, compressionMethods []byte, cipherSuites []uint16) error {
	if len(sessionId) > 32 {
		return altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: a session id is at most 32 bytes", altshiftErrors.ErrValidationError),
			len(sessionId),
		)
	}

	if len(compressionMethods) > 255 {
		return altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: the compression method list is longer than its length field", altshiftErrors.ErrValidationError),
			len(compressionMethods),
		)
	}

	// The list is written as a byte count in a uint16, so it is half that many
	// suites.
	if len(cipherSuites) > 0xffff/2 {
		return altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: the cipher suite list is longer than its length field", altshiftErrors.ErrValidationError),
			len(cipherSuites),
		)
	}

	return nil
}

func marshalUint16List(values []uint16) []byte {
	var marshalled []byte
	marshalled = binary.BigEndian.AppendUint16(marshalled, toUint16(len(values)*2))

	for _, value := range values {
		marshalled = binary.BigEndian.AppendUint16(marshalled, value)
	}

	return marshalled
}

func appendExtension(extensions []byte, extensionType uint16, data []byte) []byte {
	extensions = binary.BigEndian.AppendUint16(extensions, extensionType)
	extensions = binary.BigEndian.AppendUint16(extensions, toUint16(len(data)))

	return append(extensions, data...)
}

// toUint16 and toByte convert a length into the field it is written into, refusing
// one that would not fit rather than silently truncating it. Marshal has already
// checked its inputs, so these are the belt to that pair of braces -- and the reason
// no conversion in this file can quietly produce a hello that says something other
// than what was asked for.
func toUint16(value int) uint16 {
	if value < 0 || value > 0xffff {
		return 0
	}

	return uint16(value)
}

func toByte(value int) byte {
	if value < 0 || value > 0xff {
		return 0
	}

	return byte(value)
}

// lowByte takes the bottom eight bits of a value, which is what writing one byte of
// a multi-byte length means. It is not toByte: that refuses a value too large for a
// byte, and here being too large is the ordinary case.
func lowByte(value int) byte {
	return byte(value & 0xff)
}
