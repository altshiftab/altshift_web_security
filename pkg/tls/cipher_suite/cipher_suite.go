package cipher_suite

import (
	"sort"

	"github.com/altshiftab/altshift_web_security/pkg/tls/wire"
)

// tls13Version is where the disjoint registry begins.
const tls13Version = wire.VersionTls13

// KeyExchange is how the session key is agreed, which decides two things a probe
// needs: whether the exchange offers forward secrecy, and how to read the
// ServerKeyExchange message that carries its parameters.
type KeyExchange string

const (
	KeyExchangeEcdhe      KeyExchange = "ECDHE"
	KeyExchangeDhe        KeyExchange = "DHE"
	KeyExchangeRsa        KeyExchange = "RSA"
	KeyExchangeDhAnon     KeyExchange = "DH_anon"
	KeyExchangeEcdhAnon   KeyExchange = "ECDH_anon"
	KeyExchangeNegotiated KeyExchange = "negotiated"
)

// Authentication is what proves the server is who it says it is. Anonymous means
// nothing does.
type Authentication string

const (
	AuthenticationRsa         Authentication = "RSA"
	AuthenticationEcdsa       Authentication = "ECDSA"
	AuthenticationDss         Authentication = "DSS"
	AuthenticationAnonymous   Authentication = "anonymous"
	AuthenticationCertificate Authentication = "certificate"
)

// Category is what the policy makes of a suite.
type Category string

const (
	CategoryGood         Category = "good"
	CategorySufficient   Category = "sufficient"
	CategoryPhaseOut     Category = "phase out"
	CategoryInsufficient Category = "insufficient"
)

// Rank orders the categories from best to worst, which is what the ordering check
// compares against.
func (category Category) Rank() int {
	switch category {
	case CategoryGood:
		return 0
	case CategorySufficient:
		return 1
	case CategoryPhaseOut:
		return 2
	case CategoryInsufficient:
		return 3
	default:
		return 4
	}
}

// Suite is one entry of the IANA registry, as much of it as the checks need.
type Suite struct {
	Id          uint16
	Name        string
	KeyExchange KeyExchange
	// Authentication is what signs the exchange. TLS 1.3 leaves it to the
	// certificate rather than naming it in the suite.
	Authentication Authentication
	// MinVersion is the oldest version that may negotiate this suite. There is no
	// maximum: the TLS 1.3 registry is disjoint from everything before it, so a
	// suite belongs to 1.3 exactly when its minimum is 1.3, and IsTls13 says so.
	MinVersion uint16
}

// IsTls13 reports whether this suite belongs to the TLS 1.3 registry, which is
// disjoint from every version before it. A 1.3 hello must offer only these, and a
// 1.2 hello none of them.
func (suite *Suite) IsTls13() bool {
	if suite == nil {
		return false
	}

	return suite.MinVersion == tls13Version
}

// FiniteField reports whether the exchange is over a finite field rather than a
// curve. It decides how the ServerKeyExchange is read, and reading it wrong turns
// the high byte of a prime length into a curve identifier.
func (suite *Suite) FiniteField() bool {
	if suite == nil {
		return false
	}

	return suite.KeyExchange == KeyExchangeDhe || suite.KeyExchange == KeyExchangeDhAnon
}

// ForwardSecrecy reports whether a recorded session stays private once the server's
// key is lost.
func (suite *Suite) ForwardSecrecy() bool {
	if suite == nil {
		return false
	}

	switch suite.KeyExchange {
	case KeyExchangeEcdhe, KeyExchangeDhe, KeyExchangeNegotiated:
		return true
	default:
		return false
	}
}

// Category is what the policy makes of this suite.
func (suite *Suite) Category() Category {
	if suite == nil {
		return CategoryInsufficient
	}

	switch {
	case good[suite.Name]:
		return CategoryGood
	case sufficient[suite.Name]:
		return CategorySufficient
	case phaseOut[suite.Name]:
		return CategoryPhaseOut
	default:
		return CategoryInsufficient
	}
}

// ById finds a suite by its wire value. An unknown value returns nil, and the
// analysis reports it by number: the registry grows, and a suite this does not know
// is a fact about the catalogue rather than about the server.
func ById(id uint16) *Suite {
	return byId[id]
}

// Name is what to call a suite in a report, falling back to the number.
func Name(id uint16) string {
	if suite := ById(id); suite != nil {
		return suite.Name
	}

	return "unknown suite " + hex(id)
}

// Categorize is the policy verdict on a suite by its wire value.
func Categorize(id uint16) Category {
	return ById(id).Category()
}

// ForVersion is every suite that may be negotiated at a version, which is what a
// probe offers when it wants to know what a server will take. The order is by
// registry value so that a run is reproducible; what the server picks out of it is
// the server's preference, not this list's.
func ForVersion(version uint16) []uint16 {
	var ids []uint16

	for _, suite := range catalogue {
		// The two registries do not mix. Offering a TLS 1.2 suite in a 1.3 hello
		// is noise the server must ignore, and offering a 1.3 suite to a 1.2
		// server is a suite it cannot pick -- which, during an enumeration, reads
		// as the server having run out of suites it will accept.
		if suite.IsTls13() != (version >= tls13Version) {
			continue
		}

		if version < suite.MinVersion {
			continue
		}

		ids = append(ids, suite.Id)
	}

	sort.Slice(ids, func(i int, j int) bool { return ids[i] < ids[j] })

	return ids
}

// All is every suite in the catalogue.
func All() []*Suite {
	return catalogue
}

func hex(id uint16) string {
	const digits = "0123456789abcdef"

	return "0x" + string([]byte{
		digits[id>>12&0xf],
		digits[id>>8&0xf],
		digits[id>>4&0xf],
		digits[id&0xf],
	})
}

var byId = func() map[uint16]*Suite {
	index := make(map[uint16]*Suite, len(catalogue))
	for _, suite := range catalogue {
		index[suite.Id] = suite
	}

	return index
}()

func nameSet(names []string) map[string]bool {
	set := make(map[string]bool, len(names))
	for _, name := range names {
		set[name] = true
	}

	return set
}
