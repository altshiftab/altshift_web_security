package cipher_suite

import (
	"github.com/altshiftab/altshift_web_security/pkg/tls/wire"
)

// catalogue is the part of the IANA TLS cipher suite registry these checks need.
//
// It covers what is worth *detecting*, not what is worth using: the RC4, DES,
// export, anonymous and null suites are here precisely because a server offering one
// is the finding. A suite absent from this table can still be reported -- the
// analysis names it by number -- but it cannot be offered, and a server that only
// speaks suites missing from here would look like a server that speaks none.
//
// MinVersion is the oldest version that may negotiate the suite. The AEAD and
// SHA-2 suites arrived with TLS 1.2 and a server must not pick one below it; the
// rest go back to SSL 3.0. Offering a suite below its minimum version is how a
// probe gets a handshake failure that looks like a refused version.
var catalogue = []*Suite{
	// TLS 1.3. The suite no longer names the exchange or the authentication:
	// both are settled by the key share and the certificate.
	{Id: 0x1301, Name: "TLS_AES_128_GCM_SHA256", KeyExchange: KeyExchangeNegotiated, Authentication: AuthenticationCertificate, MinVersion: wire.VersionTls13},
	{Id: 0x1302, Name: "TLS_AES_256_GCM_SHA384", KeyExchange: KeyExchangeNegotiated, Authentication: AuthenticationCertificate, MinVersion: wire.VersionTls13},
	{Id: 0x1303, Name: "TLS_CHACHA20_POLY1305_SHA256", KeyExchange: KeyExchangeNegotiated, Authentication: AuthenticationCertificate, MinVersion: wire.VersionTls13},
	{Id: 0x1304, Name: "TLS_AES_128_CCM_SHA256", KeyExchange: KeyExchangeNegotiated, Authentication: AuthenticationCertificate, MinVersion: wire.VersionTls13},
	// The one TLS 1.3 suite the policy rejects: an eight-byte tag is too short.
	{Id: 0x1305, Name: "TLS_AES_128_CCM_8_SHA256", KeyExchange: KeyExchangeNegotiated, Authentication: AuthenticationCertificate, MinVersion: wire.VersionTls13},

	// ECDHE with ECDSA authentication.
	{Id: 0xc02b, Name: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", KeyExchange: KeyExchangeEcdhe, Authentication: AuthenticationEcdsa, MinVersion: wire.VersionTls12},
	{Id: 0xc02c, Name: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", KeyExchange: KeyExchangeEcdhe, Authentication: AuthenticationEcdsa, MinVersion: wire.VersionTls12},
	{Id: 0xcca9, Name: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", KeyExchange: KeyExchangeEcdhe, Authentication: AuthenticationEcdsa, MinVersion: wire.VersionTls12},
	{Id: 0xc0ac, Name: "TLS_ECDHE_ECDSA_WITH_AES_128_CCM", KeyExchange: KeyExchangeEcdhe, Authentication: AuthenticationEcdsa, MinVersion: wire.VersionTls12},
	{Id: 0xc0ad, Name: "TLS_ECDHE_ECDSA_WITH_AES_256_CCM", KeyExchange: KeyExchangeEcdhe, Authentication: AuthenticationEcdsa, MinVersion: wire.VersionTls12},
	{Id: 0xc0ae, Name: "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8", KeyExchange: KeyExchangeEcdhe, Authentication: AuthenticationEcdsa, MinVersion: wire.VersionTls12},
	{Id: 0xc0af, Name: "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8", KeyExchange: KeyExchangeEcdhe, Authentication: AuthenticationEcdsa, MinVersion: wire.VersionTls12},
	{Id: 0xc023, Name: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", KeyExchange: KeyExchangeEcdhe, Authentication: AuthenticationEcdsa, MinVersion: wire.VersionTls12},
	{Id: 0xc024, Name: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", KeyExchange: KeyExchangeEcdhe, Authentication: AuthenticationEcdsa, MinVersion: wire.VersionTls12},
	{Id: 0xc009, Name: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", KeyExchange: KeyExchangeEcdhe, Authentication: AuthenticationEcdsa, MinVersion: wire.VersionSsl30},
	{Id: 0xc00a, Name: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", KeyExchange: KeyExchangeEcdhe, Authentication: AuthenticationEcdsa, MinVersion: wire.VersionSsl30},
	{Id: 0xc007, Name: "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", KeyExchange: KeyExchangeEcdhe, Authentication: AuthenticationEcdsa, MinVersion: wire.VersionSsl30},
	{Id: 0xc008, Name: "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA", KeyExchange: KeyExchangeEcdhe, Authentication: AuthenticationEcdsa, MinVersion: wire.VersionSsl30},
	{Id: 0xc006, Name: "TLS_ECDHE_ECDSA_WITH_NULL_SHA", KeyExchange: KeyExchangeEcdhe, Authentication: AuthenticationEcdsa, MinVersion: wire.VersionSsl30},
	{Id: 0xc072, Name: "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256", KeyExchange: KeyExchangeEcdhe, Authentication: AuthenticationEcdsa, MinVersion: wire.VersionTls12},
	{Id: 0xc073, Name: "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384", KeyExchange: KeyExchangeEcdhe, Authentication: AuthenticationEcdsa, MinVersion: wire.VersionTls12},
	{Id: 0xc086, Name: "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256", KeyExchange: KeyExchangeEcdhe, Authentication: AuthenticationEcdsa, MinVersion: wire.VersionTls12},
	{Id: 0xc087, Name: "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384", KeyExchange: KeyExchangeEcdhe, Authentication: AuthenticationEcdsa, MinVersion: wire.VersionTls12},
	{Id: 0xc048, Name: "TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256", KeyExchange: KeyExchangeEcdhe, Authentication: AuthenticationEcdsa, MinVersion: wire.VersionTls12},
	{Id: 0xc049, Name: "TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384", KeyExchange: KeyExchangeEcdhe, Authentication: AuthenticationEcdsa, MinVersion: wire.VersionTls12},
	{Id: 0xc05c, Name: "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256", KeyExchange: KeyExchangeEcdhe, Authentication: AuthenticationEcdsa, MinVersion: wire.VersionTls12},
	{Id: 0xc05d, Name: "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384", KeyExchange: KeyExchangeEcdhe, Authentication: AuthenticationEcdsa, MinVersion: wire.VersionTls12},

	// ECDHE with RSA authentication.
	{Id: 0xc02f, Name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", KeyExchange: KeyExchangeEcdhe, Authentication: AuthenticationRsa, MinVersion: wire.VersionTls12},
	{Id: 0xc030, Name: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", KeyExchange: KeyExchangeEcdhe, Authentication: AuthenticationRsa, MinVersion: wire.VersionTls12},
	{Id: 0xcca8, Name: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", KeyExchange: KeyExchangeEcdhe, Authentication: AuthenticationRsa, MinVersion: wire.VersionTls12},
	{Id: 0xc027, Name: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", KeyExchange: KeyExchangeEcdhe, Authentication: AuthenticationRsa, MinVersion: wire.VersionTls12},
	{Id: 0xc028, Name: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", KeyExchange: KeyExchangeEcdhe, Authentication: AuthenticationRsa, MinVersion: wire.VersionTls12},
	{Id: 0xc013, Name: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", KeyExchange: KeyExchangeEcdhe, Authentication: AuthenticationRsa, MinVersion: wire.VersionSsl30},
	{Id: 0xc014, Name: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", KeyExchange: KeyExchangeEcdhe, Authentication: AuthenticationRsa, MinVersion: wire.VersionSsl30},
	{Id: 0xc011, Name: "TLS_ECDHE_RSA_WITH_RC4_128_SHA", KeyExchange: KeyExchangeEcdhe, Authentication: AuthenticationRsa, MinVersion: wire.VersionSsl30},
	{Id: 0xc012, Name: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", KeyExchange: KeyExchangeEcdhe, Authentication: AuthenticationRsa, MinVersion: wire.VersionSsl30},
	{Id: 0xc010, Name: "TLS_ECDHE_RSA_WITH_NULL_SHA", KeyExchange: KeyExchangeEcdhe, Authentication: AuthenticationRsa, MinVersion: wire.VersionSsl30},
	{Id: 0xc076, Name: "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256", KeyExchange: KeyExchangeEcdhe, Authentication: AuthenticationRsa, MinVersion: wire.VersionTls12},
	{Id: 0xc077, Name: "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384", KeyExchange: KeyExchangeEcdhe, Authentication: AuthenticationRsa, MinVersion: wire.VersionTls12},
	{Id: 0xc08a, Name: "TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256", KeyExchange: KeyExchangeEcdhe, Authentication: AuthenticationRsa, MinVersion: wire.VersionTls12},
	{Id: 0xc08b, Name: "TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384", KeyExchange: KeyExchangeEcdhe, Authentication: AuthenticationRsa, MinVersion: wire.VersionTls12},
	{Id: 0xc04c, Name: "TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256", KeyExchange: KeyExchangeEcdhe, Authentication: AuthenticationRsa, MinVersion: wire.VersionTls12},
	{Id: 0xc04d, Name: "TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384", KeyExchange: KeyExchangeEcdhe, Authentication: AuthenticationRsa, MinVersion: wire.VersionTls12},
	{Id: 0xc060, Name: "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256", KeyExchange: KeyExchangeEcdhe, Authentication: AuthenticationRsa, MinVersion: wire.VersionTls12},
	{Id: 0xc061, Name: "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384", KeyExchange: KeyExchangeEcdhe, Authentication: AuthenticationRsa, MinVersion: wire.VersionTls12},

	// DHE with RSA authentication. Forward secret, but over a finite field, which
	// the 2025 policy puts on its way out however large the group.
	{Id: 0x009e, Name: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", KeyExchange: KeyExchangeDhe, Authentication: AuthenticationRsa, MinVersion: wire.VersionTls12},
	{Id: 0x009f, Name: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", KeyExchange: KeyExchangeDhe, Authentication: AuthenticationRsa, MinVersion: wire.VersionTls12},
	{Id: 0xccaa, Name: "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256", KeyExchange: KeyExchangeDhe, Authentication: AuthenticationRsa, MinVersion: wire.VersionTls12},
	{Id: 0xc09e, Name: "TLS_DHE_RSA_WITH_AES_128_CCM", KeyExchange: KeyExchangeDhe, Authentication: AuthenticationRsa, MinVersion: wire.VersionTls12},
	{Id: 0xc09f, Name: "TLS_DHE_RSA_WITH_AES_256_CCM", KeyExchange: KeyExchangeDhe, Authentication: AuthenticationRsa, MinVersion: wire.VersionTls12},
	{Id: 0xc0a2, Name: "TLS_DHE_RSA_WITH_AES_128_CCM_8", KeyExchange: KeyExchangeDhe, Authentication: AuthenticationRsa, MinVersion: wire.VersionTls12},
	{Id: 0xc0a3, Name: "TLS_DHE_RSA_WITH_AES_256_CCM_8", KeyExchange: KeyExchangeDhe, Authentication: AuthenticationRsa, MinVersion: wire.VersionTls12},
	{Id: 0x0067, Name: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", KeyExchange: KeyExchangeDhe, Authentication: AuthenticationRsa, MinVersion: wire.VersionTls12},
	{Id: 0x006b, Name: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", KeyExchange: KeyExchangeDhe, Authentication: AuthenticationRsa, MinVersion: wire.VersionTls12},
	{Id: 0x0033, Name: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", KeyExchange: KeyExchangeDhe, Authentication: AuthenticationRsa, MinVersion: wire.VersionSsl30},
	{Id: 0x0039, Name: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA", KeyExchange: KeyExchangeDhe, Authentication: AuthenticationRsa, MinVersion: wire.VersionSsl30},
	{Id: 0x0016, Name: "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", KeyExchange: KeyExchangeDhe, Authentication: AuthenticationRsa, MinVersion: wire.VersionSsl30},
	{Id: 0x0015, Name: "TLS_DHE_RSA_WITH_DES_CBC_SHA", KeyExchange: KeyExchangeDhe, Authentication: AuthenticationRsa, MinVersion: wire.VersionSsl30},
	{Id: 0x0045, Name: "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA", KeyExchange: KeyExchangeDhe, Authentication: AuthenticationRsa, MinVersion: wire.VersionSsl30},
	{Id: 0x0088, Name: "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA", KeyExchange: KeyExchangeDhe, Authentication: AuthenticationRsa, MinVersion: wire.VersionSsl30},
	{Id: 0x00be, Name: "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256", KeyExchange: KeyExchangeDhe, Authentication: AuthenticationRsa, MinVersion: wire.VersionTls12},
	{Id: 0x00c4, Name: "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256", KeyExchange: KeyExchangeDhe, Authentication: AuthenticationRsa, MinVersion: wire.VersionTls12},
	{Id: 0xc07c, Name: "TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256", KeyExchange: KeyExchangeDhe, Authentication: AuthenticationRsa, MinVersion: wire.VersionTls12},
	{Id: 0xc07d, Name: "TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384", KeyExchange: KeyExchangeDhe, Authentication: AuthenticationRsa, MinVersion: wire.VersionTls12},
	{Id: 0xc044, Name: "TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256", KeyExchange: KeyExchangeDhe, Authentication: AuthenticationRsa, MinVersion: wire.VersionTls12},
	{Id: 0xc045, Name: "TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384", KeyExchange: KeyExchangeDhe, Authentication: AuthenticationRsa, MinVersion: wire.VersionTls12},
	{Id: 0xc052, Name: "TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256", KeyExchange: KeyExchangeDhe, Authentication: AuthenticationRsa, MinVersion: wire.VersionTls12},
	{Id: 0xc053, Name: "TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384", KeyExchange: KeyExchangeDhe, Authentication: AuthenticationRsa, MinVersion: wire.VersionTls12},

	// DHE with DSS authentication.
	{Id: 0x0032, Name: "TLS_DHE_DSS_WITH_AES_128_CBC_SHA", KeyExchange: KeyExchangeDhe, Authentication: AuthenticationDss, MinVersion: wire.VersionSsl30},
	{Id: 0x0038, Name: "TLS_DHE_DSS_WITH_AES_256_CBC_SHA", KeyExchange: KeyExchangeDhe, Authentication: AuthenticationDss, MinVersion: wire.VersionSsl30},
	{Id: 0x0040, Name: "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256", KeyExchange: KeyExchangeDhe, Authentication: AuthenticationDss, MinVersion: wire.VersionTls12},
	{Id: 0x006a, Name: "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256", KeyExchange: KeyExchangeDhe, Authentication: AuthenticationDss, MinVersion: wire.VersionTls12},
	{Id: 0x0013, Name: "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA", KeyExchange: KeyExchangeDhe, Authentication: AuthenticationDss, MinVersion: wire.VersionSsl30},

	// Static RSA: no forward secrecy, so insufficient whatever the cipher.
	{Id: 0x009c, Name: "TLS_RSA_WITH_AES_128_GCM_SHA256", KeyExchange: KeyExchangeRsa, Authentication: AuthenticationRsa, MinVersion: wire.VersionTls12},
	{Id: 0x009d, Name: "TLS_RSA_WITH_AES_256_GCM_SHA384", KeyExchange: KeyExchangeRsa, Authentication: AuthenticationRsa, MinVersion: wire.VersionTls12},
	{Id: 0x003c, Name: "TLS_RSA_WITH_AES_128_CBC_SHA256", KeyExchange: KeyExchangeRsa, Authentication: AuthenticationRsa, MinVersion: wire.VersionTls12},
	{Id: 0x003d, Name: "TLS_RSA_WITH_AES_256_CBC_SHA256", KeyExchange: KeyExchangeRsa, Authentication: AuthenticationRsa, MinVersion: wire.VersionTls12},
	{Id: 0x002f, Name: "TLS_RSA_WITH_AES_128_CBC_SHA", KeyExchange: KeyExchangeRsa, Authentication: AuthenticationRsa, MinVersion: wire.VersionSsl30},
	{Id: 0x0035, Name: "TLS_RSA_WITH_AES_256_CBC_SHA", KeyExchange: KeyExchangeRsa, Authentication: AuthenticationRsa, MinVersion: wire.VersionSsl30},
	{Id: 0x000a, Name: "TLS_RSA_WITH_3DES_EDE_CBC_SHA", KeyExchange: KeyExchangeRsa, Authentication: AuthenticationRsa, MinVersion: wire.VersionSsl30},
	{Id: 0x0005, Name: "TLS_RSA_WITH_RC4_128_SHA", KeyExchange: KeyExchangeRsa, Authentication: AuthenticationRsa, MinVersion: wire.VersionSsl30},
	{Id: 0x0004, Name: "TLS_RSA_WITH_RC4_128_MD5", KeyExchange: KeyExchangeRsa, Authentication: AuthenticationRsa, MinVersion: wire.VersionSsl30},
	{Id: 0x0009, Name: "TLS_RSA_WITH_DES_CBC_SHA", KeyExchange: KeyExchangeRsa, Authentication: AuthenticationRsa, MinVersion: wire.VersionSsl30},
	{Id: 0x0096, Name: "TLS_RSA_WITH_SEED_CBC_SHA", KeyExchange: KeyExchangeRsa, Authentication: AuthenticationRsa, MinVersion: wire.VersionSsl30},
	{Id: 0x0007, Name: "TLS_RSA_WITH_IDEA_CBC_SHA", KeyExchange: KeyExchangeRsa, Authentication: AuthenticationRsa, MinVersion: wire.VersionSsl30},
	{Id: 0x0041, Name: "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA", KeyExchange: KeyExchangeRsa, Authentication: AuthenticationRsa, MinVersion: wire.VersionSsl30},
	{Id: 0x0084, Name: "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA", KeyExchange: KeyExchangeRsa, Authentication: AuthenticationRsa, MinVersion: wire.VersionSsl30},
	{Id: 0x0001, Name: "TLS_RSA_WITH_NULL_MD5", KeyExchange: KeyExchangeRsa, Authentication: AuthenticationRsa, MinVersion: wire.VersionSsl30},
	{Id: 0x0002, Name: "TLS_RSA_WITH_NULL_SHA", KeyExchange: KeyExchangeRsa, Authentication: AuthenticationRsa, MinVersion: wire.VersionSsl30},
	{Id: 0x003b, Name: "TLS_RSA_WITH_NULL_SHA256", KeyExchange: KeyExchangeRsa, Authentication: AuthenticationRsa, MinVersion: wire.VersionTls12},

	// Export grade: deliberately weakened to a key length that was breakable when
	// it was standardised, and is trivial now.
	{Id: 0x0003, Name: "TLS_RSA_EXPORT_WITH_RC4_40_MD5", KeyExchange: KeyExchangeRsa, Authentication: AuthenticationRsa, MinVersion: wire.VersionSsl30},
	{Id: 0x0006, Name: "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5", KeyExchange: KeyExchangeRsa, Authentication: AuthenticationRsa, MinVersion: wire.VersionSsl30},
	{Id: 0x0008, Name: "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", KeyExchange: KeyExchangeRsa, Authentication: AuthenticationRsa, MinVersion: wire.VersionSsl30},
	{Id: 0x0011, Name: "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA", KeyExchange: KeyExchangeDhe, Authentication: AuthenticationDss, MinVersion: wire.VersionSsl30},
	{Id: 0x0014, Name: "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA", KeyExchange: KeyExchangeDhe, Authentication: AuthenticationRsa, MinVersion: wire.VersionSsl30},

	// Anonymous: encrypted, and to nobody in particular.
	{Id: 0x0018, Name: "TLS_DH_anon_WITH_RC4_128_MD5", KeyExchange: KeyExchangeDhAnon, Authentication: AuthenticationAnonymous, MinVersion: wire.VersionSsl30},
	{Id: 0x001b, Name: "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA", KeyExchange: KeyExchangeDhAnon, Authentication: AuthenticationAnonymous, MinVersion: wire.VersionSsl30},
	{Id: 0x0034, Name: "TLS_DH_anon_WITH_AES_128_CBC_SHA", KeyExchange: KeyExchangeDhAnon, Authentication: AuthenticationAnonymous, MinVersion: wire.VersionSsl30},
	{Id: 0x003a, Name: "TLS_DH_anon_WITH_AES_256_CBC_SHA", KeyExchange: KeyExchangeDhAnon, Authentication: AuthenticationAnonymous, MinVersion: wire.VersionSsl30},
	{Id: 0xc016, Name: "TLS_ECDH_anon_WITH_RC4_128_SHA", KeyExchange: KeyExchangeEcdhAnon, Authentication: AuthenticationAnonymous, MinVersion: wire.VersionSsl30},
	{Id: 0xc017, Name: "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA", KeyExchange: KeyExchangeEcdhAnon, Authentication: AuthenticationAnonymous, MinVersion: wire.VersionSsl30},
	{Id: 0xc018, Name: "TLS_ECDH_anon_WITH_AES_128_CBC_SHA", KeyExchange: KeyExchangeEcdhAnon, Authentication: AuthenticationAnonymous, MinVersion: wire.VersionSsl30},
	{Id: 0xc019, Name: "TLS_ECDH_anon_WITH_AES_256_CBC_SHA", KeyExchange: KeyExchangeEcdhAnon, Authentication: AuthenticationAnonymous, MinVersion: wire.VersionSsl30},
}
