package rule_id

const (
	// The protocol versions a server will speak. SSL 3.0 and below are broken
	// outright; TLS 1.0 and 1.1 are retired but need an active attacker.
	Ssl30Supported    = "tls_version_ssl30_supported"
	Tls10Supported    = "tls_version_tls10_supported"
	Tls11Supported    = "tls_version_tls11_supported"
	Tls13NotSupported = "tls_version_tls13_not_supported"

	// The cipher suites it will negotiate, one result per category rather than
	// one per suite.
	CipherSuiteInsufficient = "tls_cipher_suite_insufficient"
	CipherSuitePhaseOut     = "tls_cipher_suite_phase_out"

	// Whether it imposes its own preference, and whether that preference is
	// ordered the way the policy wants.
	CipherSuiteOrderViolation   = "tls_cipher_suite_order_violation"
	CipherSuiteOrderNotEnforced = "tls_cipher_suite_order_not_enforced"

	// The group the key exchange is done over.
	KeyExchangeGroupInsufficient = "tls_key_exchange_group_insufficient"
	KeyExchangeGroupPhaseOut     = "tls_key_exchange_group_phase_out"
	KeyExchangeGroupWeakAccepted = "tls_key_exchange_group_weak_accepted"
	KeyExchangeFiniteFieldSmall  = "tls_key_exchange_finite_field_small"

	// The hash the key exchange is signed with.
	//nolint:gosec // A rule id naming a hash function, not a credential.
	KeyExchangeHashSha1   = "tls_key_exchange_hash_sha1"
	KeyExchangeHashSha224 = "tls_key_exchange_hash_sha224"

	CompressionEnabled = "tls_compression_enabled"

	SecureRenegotiationUnsupported = "tls_secure_renegotiation_unsupported"

	ZeroRttEnabled = "tls_zero_rtt_enabled"

	OcspStaplingMissing = "tls_ocsp_stapling_missing"

	//nolint:gosec // A rule id naming a TLS extension, not a credential.
	ExtendedMasterSecretUnsupported = "tls_extended_master_secret_unsupported"

	// CheckNotDetermined stands for any check that could not be run, carrying the
	// name of the check and the reason in its properties. It is one rule rather
	// than one per check because what a reader needs is the list of what is not
	// known, and a rule table holding a dozen near-identical entries buries it.
	CheckNotDetermined = "tls_check_not_determined"
)
