// Package observation holds what a probe saw, as data with no opinion about it.
//
// It is the seam between the two halves of the TLS checks. The probe fills one of
// these in over the network and forms no judgement; the analysis reads one and never
// opens a socket. That split is what makes both testable: an analysis test builds an
// Observation from a composite literal, and a probe test asserts on the one it
// returns without needing to know what the policy makes of it.
//
// Nothing here has methods. A reader that needs to reach through a chain of optional
// pointers finds one in the analysis, so the guards live where nilaway can see them
// rather than being spread over every caller.
package observation

// Target is what was probed.
type Target struct {
	Host string
	Port int
	// ServerName is what was sent as SNI, which is the host unless overridden.
	ServerName string
}

// Observation is everything one run learned.
type Observation struct {
	Target *Target
	// Versions is one entry per version attempted, oldest first.
	Versions      []*Version
	Groups        *Groups
	Signature     *Signature
	Compression   *Compression
	Renegotiation *Renegotiation
	Order         *Order
	Session       *Session
	// Incomplete names the phases that were cut short, by a connection budget, a
	// timeout, or a server that stopped answering. A check whose phase is here is
	// reported as undetermined rather than as a pass.
	Incomplete []*Phase
}

// Version is what one protocol version probe found.
type Version struct {
	Version uint16
	// Attempted is false for a version that was never tried, which is how a
	// budget that ran out is told from a version that was refused.
	Attempted bool
	Accepted  bool
	// AlertDescription is what the server said when it refused. A protocol_version
	// alert means the version itself was refused; a handshake_failure means no
	// suite was mutually acceptable, which is a different finding and a common
	// false negative.
	AlertDescription *uint8
	// TransportError is set when the connection failed rather than the handshake.
	TransportError string
	// CipherSuites are the suites the server accepted at this version, in the
	// order it chose them -- which is its own preference order when it has one.
	CipherSuites []uint16
	// CipherSuitesComplete is false when the enumeration was cut short, so a
	// server may accept more than are listed.
	CipherSuitesComplete bool
	// SelectedGroup is the group the server chose for the key exchange.
	SelectedGroup *uint16
	// FiniteField describes the group when the exchange was over one.
	FiniteField *FiniteField
	// SignatureAlgorithm is what signed the key exchange, which below TLS 1.3 is
	// stated in the clear. At 1.3 the signature is encrypted and this is nil.
	SignatureAlgorithm *uint16
	// ExtendedMasterSecret and SecureRenegotiation are whether the server echoed
	// the extension. Both are meaningless at TLS 1.3, which has no such choice to
	// make, and are left nil there.
	ExtendedMasterSecret *bool
	SecureRenegotiation  *bool
}

// FiniteField is a finite-field group, which is described by its size rather than
// named. Whether it is one of the standard groups is not something a handshake says.
type FiniteField struct {
	PrimeBits      int
	GeneratorIsTwo bool
}

// Groups is what the key exchange was done over.
type Groups struct {
	Tested bool
	// Selected is the group chosen at each negotiated version.
	Selected map[uint16]uint16
	// WeakAccepted are groups the server agreed to when it was offered nothing
	// better, which says more than what it prefers.
	WeakAccepted []uint16
}

// Signature is what signed the key exchange.
type Signature struct {
	Tested bool
	// Chosen is the algorithm on the ServerKeyExchange of an ordinary TLS 1.2
	// handshake.
	Chosen *uint16
	// Sha1Accepted and Sha224Accepted are whether the server completed a
	// handshake that offered only those hashes. Nil means it was not determined.
	Sha1Accepted   *bool
	Sha224Accepted *bool
}

// Compression is whether the server will compress records, which is the CRIME
// exposure.
type Compression struct {
	Tested bool
	// Applicable is false against a server that speaks only TLS 1.3, which has no
	// compression to enable.
	Applicable bool
	// Selected is the compression method the server chose; anything but zero is
	// the finding.
	Selected *uint8
}

// Renegotiation covers both renegotiation checks.
type Renegotiation struct {
	// SecureSupported is whether the server sent renegotiation_info, and is nil
	// where no version below TLS 1.3 was accepted.
	SecureSupported *bool
	// ClientInitiatedPossible is false when the server accepts only TLS 1.3, which
	// forbids renegotiation outright. It is nil otherwise: determining it needs a
	// working record layer, which this does not have.
	ClientInitiatedPossible *bool
	// ClientInitiatedReason says why it was not determined.
	ClientInitiatedReason string
}

// Order is whether the server imposes its own cipher suite preference.
type Order struct {
	Tested bool
	// Applicable is false against a server that speaks only TLS 1.3, where there
	// is nothing to order that is not already acceptable.
	Applicable bool
	// ServerEnforces is whether the server picked the same suite whichever order
	// it was offered them in.
	ServerEnforces *bool
	// Violation is the pair {chosen, better} where the server preferred a suite
	// over one the policy ranks higher.
	Violation []uint16
	// ViolationVersion is where that happened.
	ViolationVersion uint16
}

// Session is what an ordinary completed handshake showed. It comes from the standard
// library rather than from a raw probe: these are the two checks that need a
// handshake that finishes.
type Session struct {
	Established bool
	Version     uint16
	CipherSuite uint16
	OcspStapled bool
	EarlyData   *EarlyData
	Error       string
}

// EarlyData is whether the server offers 0-RTT, which it advertises in the session
// ticket rather than in the handshake.
type EarlyData struct {
	Determined bool
	// MaxSize is the largest early data the server will take. A ticket with the
	// extension and a size of zero is not an offer.
	MaxSize *uint32
	// Reason says why it was not determined.
	Reason string
}

// Phase is a piece of work that did not finish, and why.
type Phase struct {
	Name   string
	Reason string
}
