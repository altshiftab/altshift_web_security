package rule_id_mappings

import (
	"github.com/altshiftab/altshift_web_security/pkg/tls/connection_analysis/rule_id"
)

// Severity is the qualitative severity a rule carries, mapped onto a SARIF level for
// emission. It repeats the vocabulary the HTTP header rules use rather than sharing
// it: the two sets of rules are independent, and a shared package would couple them
// so that a change made for one had to be weighed against the other.
type Severity string

const (
	SeverityHigh   Severity = "high"
	SeverityMedium Severity = "medium"
	SeverityLow    Severity = "low"
	SeverityInfo   Severity = "info"
)

// RuleIdToSeverity, RuleIdToTitle and RuleIdToDescription are parallel lookup tables
// keyed by rule id, kept separate so that each stays readable as one body of curated
// text.
//
//nolint:dupl // deliberately parallel static tables; the shared key set is the point.
var RuleIdToSeverity = map[string]Severity{
	// SSL 3.0 is broken by POODLE, which needs only a network position and
	// patience. TLS 1.0 and 1.1 are retired for weak constructions rather than a
	// live break, so they are worth less.
	rule_id.Ssl30Supported:    SeverityHigh,
	rule_id.Tls10Supported:    SeverityMedium,
	rule_id.Tls11Supported:    SeverityMedium,
	rule_id.Tls13NotSupported: SeverityInfo,

	rule_id.CipherSuiteInsufficient: SeverityHigh,
	rule_id.CipherSuitePhaseOut:     SeverityLow,

	rule_id.CipherSuiteOrderViolation:   SeverityLow,
	rule_id.CipherSuiteOrderNotEnforced: SeverityInfo,

	rule_id.KeyExchangeGroupInsufficient: SeverityHigh,
	rule_id.KeyExchangeGroupPhaseOut:     SeverityLow,
	rule_id.KeyExchangeGroupWeakAccepted: SeverityLow,
	rule_id.KeyExchangeFiniteFieldSmall:  SeverityHigh,

	rule_id.KeyExchangeHashSha1:   SeverityHigh,
	rule_id.KeyExchangeHashSha224: SeverityLow,

	rule_id.CompressionEnabled: SeverityHigh,

	rule_id.SecureRenegotiationUnsupported: SeverityMedium,

	rule_id.ZeroRttEnabled: SeverityMedium,

	// A missing staple is a slower revocation check, not a hole: the certificate
	// remains checkable by other means.
	rule_id.OcspStaplingMissing: SeverityInfo,

	rule_id.ExtendedMasterSecretUnsupported: SeverityMedium,

	rule_id.CheckNotDetermined: SeverityInfo,
}

//nolint:dupl // see the note on RuleIdToSeverity.
var RuleIdToTitle = map[string]string{
	rule_id.Ssl30Supported:    "The server accepts SSL 3.0",
	rule_id.Tls10Supported:    "The server accepts TLS 1.0",
	rule_id.Tls11Supported:    "The server accepts TLS 1.1",
	rule_id.Tls13NotSupported: "The server does not accept TLS 1.3",

	rule_id.CipherSuiteInsufficient: "The server negotiates cipher suites that are no longer acceptable",
	rule_id.CipherSuitePhaseOut:     "The server negotiates cipher suites that are being phased out",

	rule_id.CipherSuiteOrderViolation:   "The server prefers a weaker cipher suite over a stronger one",
	rule_id.CipherSuiteOrderNotEnforced: "The server lets the client choose the cipher suite",

	rule_id.KeyExchangeGroupInsufficient: "The key exchange uses a group that is no longer acceptable",
	rule_id.KeyExchangeGroupPhaseOut:     "The key exchange uses a group that is being phased out",
	rule_id.KeyExchangeGroupWeakAccepted: "The server accepts a weak key exchange group when offered nothing better",
	rule_id.KeyExchangeFiniteFieldSmall:  "The finite-field key exchange group is too small",

	rule_id.KeyExchangeHashSha1:   "The server signs the key exchange with SHA-1",
	rule_id.KeyExchangeHashSha224: "The server signs the key exchange with SHA-224",

	rule_id.CompressionEnabled: "The server compresses TLS records",

	rule_id.SecureRenegotiationUnsupported: "The server does not support secure renegotiation",

	rule_id.ZeroRttEnabled: "The server offers 0-RTT early data",

	rule_id.OcspStaplingMissing: "The server does not staple an OCSP response",

	rule_id.ExtendedMasterSecretUnsupported: "The server does not support the extended master secret",

	rule_id.CheckNotDetermined: "A check could not be completed",
}

var RuleIdToDescription = map[string]string{
	rule_id.Ssl30Supported:    "SSL 3.0 is broken. The POODLE attack recovers plaintext from an SSL 3.0 connection using only a network position and the ability to make a victim's browser repeat a request, and the protocol has no fix: its padding is not covered by its integrity check. It should be disabled outright.",
	rule_id.Tls10Supported:    "TLS 1.0 is retired. It relies on MD5 and SHA-1 in its key derivation and signatures, and its CBC construction is what BEAST and Lucky 13 attack. Exploiting it needs an active attacker rather than a passive one, but nothing that still needs it should be served over it.",
	rule_id.Tls11Supported:    "TLS 1.1 is retired. It repaired the specific flaw BEAST used but kept the weak hashes and the padding construction that later attacks target, and no client that cannot speak TLS 1.2 is worth supporting.",
	rule_id.Tls13NotSupported: "TLS 1.3 removes the constructions the earlier versions were repeatedly broken through -- renegotiation, compression, static key exchange, and the negotiable weak ciphers -- and completes its handshake in one round trip rather than two. Supporting it alongside TLS 1.2 costs nothing.",

	rule_id.CipherSuiteInsufficient: "The server will negotiate cipher suites the policy considers no longer acceptable. Depending on the suite this means encryption that is broken (RC4, DES), an effective key length too short to matter (export grade, 3DES), no encryption at all (NULL), no authentication of the peer (anonymous), or no forward secrecy -- which leaves every recorded past session readable to whoever eventually obtains the server's private key.",
	rule_id.CipherSuitePhaseOut:     "The server will negotiate cipher suites that are on their way out. They are not broken, and are not urgent, but they are no longer the ones to be adding: the CBC constructions have a history of padding attacks, and the finite-field key exchanges are being retired in favour of elliptic curves.",

	rule_id.CipherSuiteOrderViolation:   "The server has a cipher suite preference of its own, and that preference puts a weaker suite ahead of a stronger one it also supports. A client that offers both gets the weaker, so supporting the stronger suite achieves nothing for the connections that matter.",
	rule_id.CipherSuiteOrderNotEnforced: "The server takes the first cipher suite the client offers rather than imposing its own preference. The connection is then only as good as the client's ordering, and a client with a poor one -- or an attacker able to influence it -- decides what protects the session.",

	rule_id.KeyExchangeGroupInsufficient: "The key exchange is done over a group the policy no longer accepts. The group is what the session key's secrecy rests on: one that is too small or not well studied puts every session, recorded or live, within reach of an adversary who can solve a discrete logarithm in it.",
	rule_id.KeyExchangeGroupPhaseOut:     "The key exchange is done over a group that is being phased out. Finite-field groups are sound at these sizes but are being retired in favour of elliptic curves, which reach the same strength in far less computation, and secp224r1 is at the lower edge of what remains acceptable.",
	rule_id.KeyExchangeGroupWeakAccepted: "Offered nothing but weak groups, the server agreed to one rather than refusing the connection. What a server prefers matters less than what it will accept: a client that offers only the weak group -- or an attacker who strips the strong ones from a hello in transit -- gets the weak group.",
	rule_id.KeyExchangeFiniteFieldSmall:  "The finite-field key exchange group is smaller than the policy allows. A 1024-bit group is within reach of a well-resourced adversary who precomputes against it once and then breaks every session using it, which is the Logjam attack.",

	rule_id.KeyExchangeHashSha1:   "The server signs its key exchange with SHA-1. Chosen-prefix collisions against SHA-1 are practical and have been demonstrated, and a signature is only as strong as the hash under it: an adversary who can construct a collision can forge the key exchange the connection's identity rests on.",
	rule_id.KeyExchangeHashSha224: "The server signs its key exchange with SHA-224. It is not broken, but it is being retired, and there is no reason to sign with it when SHA-256 is available everywhere it is.",

	rule_id.CompressionEnabled: "The server compresses TLS records. Compressing a stream that mixes attacker-controlled data with a secret leaks the secret through the compressed length, which is the CRIME attack: an attacker who can inject text into a request and watch the sizes recovers session cookies a byte at a time. There is no safe configuration of TLS-level compression.",

	rule_id.SecureRenegotiationUnsupported: "The server does not support the renegotiation indication extension of RFC 5746. Without it, an attacker can open a connection of their own, send a prefix of their choosing, and splice the victim's handshake onto it -- so the server attributes the attacker's request to the victim's session.",

	rule_id.ZeroRttEnabled: "The server accepts 0-RTT early data. Data sent in the first flight is not covered by the anti-replay protection the rest of the connection has, so an attacker who captures it can send it again and have it acted on twice. It is safe only where every request that could arrive this way is idempotent, which is not something the server can enforce.",

	rule_id.OcspStaplingMissing: "The server does not staple an OCSP response to its certificate. Without one, a client wanting to check whether the certificate has been revoked has to ask the certificate authority itself, which tells the authority what the client is visiting and, since such checks usually fail open, often does not happen at all.",

	rule_id.ExtendedMasterSecretUnsupported: "The server does not support the extended master secret extension of RFC 7627. Without it the master secret does not depend on the handshake that produced it, which is what the triple handshake attack exploits to make two different connections share a secret and let an attacker's session be mistaken for the victim's.",

	rule_id.CheckNotDetermined: "The check could not be completed, so nothing is reported about it either way. The properties of this result name the check and say what stopped it. It is not a pass.",
}
