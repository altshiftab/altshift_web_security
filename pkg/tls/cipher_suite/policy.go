package cipher_suite

import (
	"github.com/altshiftab/altshift_web_security/pkg/tls/wire"
)

// The policy is the NCSC-NL "IT Security Guidelines for Transport Layer Security"
// of May 2025, appendix B, as internet.nl applies it. The three lists below are its
// good, sufficient and phase-out sets verbatim; anything absent from all three is
// insufficient, which is what makes a suite the catalogue does not know insufficient
// by default rather than unclassified.
//
// The 2025 edition differs from the 2021 one in ways that change verdicts: RSA and
// ECDSA authentication moved from good to sufficient against the prospect of a
// quantum adversary, and every finite-field exchange moved to phase out. A report
// built on the older edition would disagree with internet.nl today.
var (
	good = nameSet([]string{
		"TLS_AES_256_GCM_SHA384",
		"TLS_CHACHA20_POLY1305_SHA256",
	})

	sufficient = nameSet([]string{
		"TLS_AES_128_GCM_SHA256",
		"TLS_AES_128_CCM_SHA256",
		"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		"TLS_ECDHE_ECDSA_WITH_AES_256_CCM",
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDHE_ECDSA_WITH_AES_128_CCM",
		"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	})

	phaseOut = nameSet([]string{
		"TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384",
		"TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384",
		"TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256",
		"TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256",
		"TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384",
		"TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384",
		"TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256",
		"TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256",
		"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
		"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
		"TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384",
		"TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384",
		"TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256",
		"TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
		"TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384",
		"TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384",
		"TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256",
		"TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256",
		"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
		"TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
		"TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384",
		"TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256",
		"TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256",
		"TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
		"TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384",
		"TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384",
		"TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256",
		"TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256",
		"TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
		"TLS_DHE_RSA_WITH_AES_256_CCM",
		"TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
		"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_DHE_RSA_WITH_AES_128_CCM",
		"TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
	})
)

// GoodGroups and PhaseOutGroups are the NCSC verdict on the key exchange groups, by
// their IANA identifier. A group in neither is insufficient. NCSC 3.3.2.1.
//
// The brainpool curves are named by the policy but have no TLS group identifier in
// the ranges any of these servers negotiate, so they are absent here rather than
// wrong.
var (
	GoodGroups = map[uint16]bool{
		wire.GroupSecp256r1: true,
		wire.GroupSecp384r1: true,
		wire.GroupSecp521r1: true,
		wire.GroupX25519:    true,
		wire.GroupX448:      true,
	}

	PhaseOutGroups = map[uint16]bool{
		// secp224r1
		21: true,
		// The finite-field groups: sound, but on their way out.
		wire.GroupFfdhe2048: true,
		wire.GroupFfdhe3072: true,
		wire.GroupFfdhe4096: true,
		wire.GroupFfdhe6144: true,
		wire.GroupFfdhe8192: true,
	}
)

// MinimumFiniteFieldPrimeBits is the smallest finite-field group NCSC will accept.
// Below it the exchange is insufficient rather than merely on its way out.
const MinimumFiniteFieldPrimeBits = 2048

// GroupName is what to call a group in a report.
func GroupName(group uint16) string {
	switch group {
	case 21:
		return "secp224r1"
	case wire.GroupSecp256r1:
		return "secp256r1"
	case wire.GroupSecp384r1:
		return "secp384r1"
	case wire.GroupSecp521r1:
		return "secp521r1"
	case wire.GroupX25519:
		return "x25519"
	case wire.GroupX448:
		return "x448"
	case wire.GroupFfdhe2048:
		return "ffdhe2048"
	case wire.GroupFfdhe3072:
		return "ffdhe3072"
	case wire.GroupFfdhe4096:
		return "ffdhe4096"
	case wire.GroupFfdhe6144:
		return "ffdhe6144"
	case wire.GroupFfdhe8192:
		return "ffdhe8192"
	case wire.GroupX25519MlKem768:
		return "x25519mlkem768"
	case wire.GroupSecp256r1MlKem768:
		return "secp256r1mlkem768"
	default:
		return "group " + hex(group)
	}
}

// CategorizeGroup is the policy verdict on a key exchange group.
func CategorizeGroup(group uint16) Category {
	switch {
	case GoodGroups[group]:
		return CategoryGood
	case PhaseOutGroups[group]:
		return CategoryPhaseOut
	default:
		return CategoryInsufficient
	}
}

// Signature algorithms whose hash NCSC will not accept, and those on their way out.
// NCSC 3.3.5. The value is the TLS SignatureScheme.
var (
	BadHashSignatureAlgorithms = map[uint16]string{
		0x0201: "rsa_pkcs1_sha1",
		0x0203: "ecdsa_sha1",
		0x0202: "dsa_sha1",
		0x0101: "rsa_pkcs1_md5",
	}

	PhaseOutHashSignatureAlgorithms = map[uint16]string{
		0x0301: "rsa_pkcs1_sha224",
		0x0303: "ecdsa_sha224",
		0x0302: "dsa_sha224",
	}
)

// SignatureAlgorithmName is what to call a signature algorithm in a report.
func SignatureAlgorithmName(signatureAlgorithm uint16) string {
	if name, found := BadHashSignatureAlgorithms[signatureAlgorithm]; found {
		return name
	}

	if name, found := PhaseOutHashSignatureAlgorithms[signatureAlgorithm]; found {
		return name
	}

	switch signatureAlgorithm {
	case 0x0401:
		return "rsa_pkcs1_sha256"
	case 0x0501:
		return "rsa_pkcs1_sha384"
	case 0x0601:
		return "rsa_pkcs1_sha512"
	case 0x0403:
		return "ecdsa_secp256r1_sha256"
	case 0x0503:
		return "ecdsa_secp384r1_sha384"
	case 0x0603:
		return "ecdsa_secp521r1_sha512"
	case 0x0804:
		return "rsa_pss_rsae_sha256"
	case 0x0805:
		return "rsa_pss_rsae_sha384"
	case 0x0806:
		return "rsa_pss_rsae_sha512"
	case 0x0807:
		return "ed25519"
	case 0x0808:
		return "ed448"
	default:
		return "signature algorithm " + hex(signatureAlgorithm)
	}
}
