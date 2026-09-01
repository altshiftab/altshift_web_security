package wire

// Protocol versions, on the wire. SSLv2 is here to be recognised, not spoken: its
// hello is a different format entirely.
const (
	VersionSsl20 uint16 = 0x0002
	VersionSsl30 uint16 = 0x0300
	VersionTls10 uint16 = 0x0301
	VersionTls11 uint16 = 0x0302
	VersionTls12 uint16 = 0x0303
	VersionTls13 uint16 = 0x0304
)

// VersionName gives the name a report should call a version.
func VersionName(version uint16) string {
	switch version {
	case VersionSsl20:
		return "SSL 2.0"
	case VersionSsl30:
		return "SSL 3.0"
	case VersionTls10:
		return "TLS 1.0"
	case VersionTls11:
		return "TLS 1.1"
	case VersionTls12:
		return "TLS 1.2"
	case VersionTls13:
		return "TLS 1.3"
	default:
		return "unknown"
	}
}

// Record content types.
const (
	RecordTypeChangeCipherSpec uint8 = 20
	RecordTypeAlert            uint8 = 21
	RecordTypeHandshake        uint8 = 22
	RecordTypeApplicationData  uint8 = 23
)

// Handshake message types.
const (
	HandshakeTypeClientHello       uint8 = 1
	HandshakeTypeServerHello       uint8 = 2
	HandshakeTypeNewSessionTicket  uint8 = 4
	HandshakeTypeCertificate       uint8 = 11
	HandshakeTypeServerKeyExchange uint8 = 12
	HandshakeTypeServerHelloDone   uint8 = 14
	HandshakeTypeFinished          uint8 = 20
	HandshakeTypeCertificateStatus uint8 = 22
)

// Extension numbers.
const (
	ExtensionServerName           uint16 = 0
	ExtensionStatusRequest        uint16 = 5
	ExtensionSupportedGroups      uint16 = 10
	ExtensionEcPointFormats       uint16 = 11
	ExtensionSignatureAlgorithms  uint16 = 13
	ExtensionAlpn                 uint16 = 16
	ExtensionPadding              uint16 = 21
	ExtensionExtendedMasterSecret uint16 = 23
	ExtensionSessionTicket        uint16 = 35
	ExtensionEarlyData            uint16 = 42
	ExtensionSupportedVersions    uint16 = 43
	ExtensionPskKeyExchangeModes  uint16 = 45
	ExtensionKeyShare             uint16 = 51
	ExtensionRenegotiationInfo    uint16 = 0xff01
)

// Signalling cipher suite values, which ride in the cipher suite list rather than
// in an extension.
const (
	ScsvEmptyRenegotiationInfo uint16 = 0x00ff
	ScsvFallback               uint16 = 0x5600
)

// Alert descriptions worth telling apart. A refused version and a refused cipher
// suite are different findings, and the alert is the only thing that separates them.
const (
	AlertCloseNotify        uint8 = 0
	AlertHandshakeFailure   uint8 = 40
	AlertUnrecognizedName   uint8 = 112
	AlertProtocolVersion    uint8 = 70
	AlertInsufficientSecure uint8 = 71
	AlertInappropriateFallb uint8 = 86
)

// AlertLevelFatal is the level that ends a connection; a warning alert does not,
// and servers routinely send one for an SNI they do not recognise.
const (
	AlertLevelWarning uint8 = 1
	AlertLevelFatal   uint8 = 2
)

// Named groups, by their IANA value.
const (
	GroupSecp256r1         uint16 = 23
	GroupSecp384r1         uint16 = 24
	GroupSecp521r1         uint16 = 25
	GroupX25519            uint16 = 29
	GroupX448              uint16 = 30
	GroupFfdhe2048         uint16 = 256
	GroupFfdhe3072         uint16 = 257
	GroupFfdhe4096         uint16 = 258
	GroupFfdhe6144         uint16 = 259
	GroupFfdhe8192         uint16 = 260
	GroupX25519MlKem768    uint16 = 4588
	GroupSecp256r1MlKem768 uint16 = 4587
)

// HelloRetryRequestRandom is the fixed random a ServerHello carries when it is
// really a HelloRetryRequest: the server accepted the version and the suite but
// wants a key share for a different group. RFC 8446, section 4.1.3.
var HelloRetryRequestRandom = []byte{
	0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
	0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
	0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
	0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
}
