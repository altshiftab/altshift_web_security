package cipher_suite

import (
	"testing"

	"github.com/altshiftab/altshift_web_security/pkg/tls/wire"
)

// The policy is three lists of names and the catalogue is a list of numbers, and
// nothing but this connects them. A name misspelled in either place silently
// reclassifies a suite -- a good one becomes insufficient, or worse, an insufficient
// one stops being reported because the catalogue entry it would have matched is
// spelled differently.
func TestEveryPolicyNameIsInTheCatalogue(t *testing.T) {
	t.Parallel()

	names := map[string]bool{}
	for _, suite := range catalogue {
		names[suite.Name] = true
	}

	testCases := []struct {
		name   string
		policy map[string]bool
	}{
		{name: "good", policy: good},
		{name: "sufficient", policy: sufficient},
		{name: "phase out", policy: phaseOut},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			for policyName := range testCase.policy {
				if !names[policyName] {
					t.Errorf(
						"the %s policy names %q, which no catalogue entry has: it can never be classified",
						testCase.name,
						policyName,
					)
				}
			}
		})
	}
}

func TestCatalogueIsWellFormed(t *testing.T) {
	t.Parallel()

	t.Run("no duplicate ids", func(t *testing.T) {
		t.Parallel()

		seen := map[uint16]string{}
		for _, suite := range catalogue {
			if previous, found := seen[suite.Id]; found {
				t.Errorf("id %#04x is both %q and %q", suite.Id, previous, suite.Name)
			}

			seen[suite.Id] = suite.Name
		}
	})

	t.Run("no duplicate names", func(t *testing.T) {
		t.Parallel()

		seen := map[string]uint16{}
		for _, suite := range catalogue {
			if previous, found := seen[suite.Name]; found {
				t.Errorf("%q is both %#04x and %#04x", suite.Name, previous, suite.Id)
			}

			seen[suite.Name] = suite.Id
		}
	})

	t.Run("no signalling values are offerable", func(t *testing.T) {
		t.Parallel()

		// The SCSVs are not suites. Offering one in a suite list as if it were
		// says something about renegotiation or downgrade that was not meant.
		for _, suite := range catalogue {
			if suite.Id == wire.ScsvEmptyRenegotiationInfo || suite.Id == wire.ScsvFallback {
				t.Errorf("%q is a signalling value, not a cipher suite", suite.Name)
			}
		}
	})

	t.Run("every entry has a minimum version", func(t *testing.T) {
		t.Parallel()

		for _, suite := range catalogue {
			if suite.MinVersion == 0 {
				t.Errorf("%q has no minimum version, so it would be offered to an SSL 3.0 server", suite.Name)
			}
		}
	})
}

func TestCategorize(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		id       uint16
		expected Category
	}{
		{name: "tls 1.3 aes 256", id: 0x1302, expected: CategoryGood},
		{name: "tls 1.3 chacha20", id: 0x1303, expected: CategoryGood},
		{name: "tls 1.3 aes 128", id: 0x1301, expected: CategorySufficient},
		{
			// The one TLS 1.3 suite the policy rejects, which is why it has to be
			// in the offered list rather than assumed away.
			name:     "tls 1.3 aes 128 ccm 8",
			id:       0x1305,
			expected: CategoryInsufficient,
		},
		{name: "ecdhe rsa aes 128 gcm", id: 0xc02f, expected: CategorySufficient},
		{name: "ecdhe ecdsa aes 256 gcm", id: 0xc02c, expected: CategorySufficient},
		{name: "ecdhe rsa cbc sha256 is on its way out", id: 0xc027, expected: CategoryPhaseOut},
		{
			// The 2025 edition puts every finite-field exchange on its way out,
			// however large the group. Under the 2021 edition this was sufficient.
			name:     "dhe rsa aes 128 gcm",
			id:       0x009e,
			expected: CategoryPhaseOut,
		},
		{name: "static rsa has no forward secrecy", id: 0x009c, expected: CategoryInsufficient},
		{name: "rc4", id: 0x0005, expected: CategoryInsufficient},
		{name: "3des", id: 0x000a, expected: CategoryInsufficient},
		{name: "null", id: 0x0002, expected: CategoryInsufficient},
		{name: "export", id: 0x0003, expected: CategoryInsufficient},
		{name: "anonymous", id: 0x0034, expected: CategoryInsufficient},
		{name: "a suite the catalogue does not know", id: 0xdead, expected: CategoryInsufficient},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := Categorize(testCase.id); got != testCase.expected {
				t.Errorf("Categorize(%#04x) = %q, want %q", testCase.id, got, testCase.expected)
			}
		})
	}
}

func TestSuiteProperties(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name                   string
		id                     uint16
		expectedFiniteField    bool
		expectedForwardSecrecy bool
	}{
		{name: "ecdhe is forward secret over a curve", id: 0xc02f, expectedForwardSecrecy: true},
		{
			name:                   "dhe is forward secret over a finite field",
			id:                     0x009e,
			expectedFiniteField:    true,
			expectedForwardSecrecy: true,
		},
		{name: "static rsa is neither", id: 0x009c},
		{name: "anonymous dh is a finite field", id: 0x0034, expectedFiniteField: true},
		{name: "tls 1.3 leaves the exchange to the key share", id: 0x1301, expectedForwardSecrecy: true},
		{name: "a suite the catalogue does not know", id: 0xdead},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			suite := ById(testCase.id)

			if got := suite.FiniteField(); got != testCase.expectedFiniteField {
				t.Errorf("FiniteField = %v, want %v", got, testCase.expectedFiniteField)
			}

			if got := suite.ForwardSecrecy(); got != testCase.expectedForwardSecrecy {
				t.Errorf("ForwardSecrecy = %v, want %v", got, testCase.expectedForwardSecrecy)
			}
		})
	}
}

func TestForVersion(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		version uint16
		// mustHold and mustNotHold are suites whose presence at this version is
		// the point.
		mustHold    []uint16
		mustNotHold []uint16
	}{
		{
			name:     "tls 1.3 offers only the tls 1.3 suites",
			version:  wire.VersionTls13,
			mustHold: []uint16{0x1301, 0x1302, 0x1303, 0x1304, 0x1305},
			// Offering a TLS 1.2 suite at 1.3 is a hello no server will answer.
			mustNotHold: []uint16{0xc02f, 0x009e, 0x0005},
		},
		{
			name:        "tls 1.2 offers the aead suites but not the tls 1.3 ones",
			version:     wire.VersionTls12,
			mustHold:    []uint16{0xc02f, 0xc02b, 0x009e, 0x0005, 0x000a},
			mustNotHold: []uint16{0x1301, 0x1302},
		},
		{
			// A suite that arrived with TLS 1.2 offered to a TLS 1.0 server draws
			// a handshake failure, which reads exactly like a refused version.
			name:        "tls 1.0 offers nothing that postdates it",
			version:     wire.VersionTls10,
			mustHold:    []uint16{0xc013, 0x002f, 0x0005},
			mustNotHold: []uint16{0xc02f, 0x1301, 0x009e, 0xc027},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			offered := map[uint16]bool{}
			for _, id := range ForVersion(testCase.version) {
				offered[id] = true
			}

			if len(offered) == 0 {
				t.Fatal("nothing at all would be offered")
			}

			for _, id := range testCase.mustHold {
				if !offered[id] {
					t.Errorf("%s is not offered at %s", Name(id), wire.VersionName(testCase.version))
				}
			}

			for _, id := range testCase.mustNotHold {
				if offered[id] {
					t.Errorf("%s is offered at %s, which cannot negotiate it", Name(id), wire.VersionName(testCase.version))
				}
			}
		})
	}
}

func TestCategorizeGroup(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		group    uint16
		expected Category
	}{
		{name: "x25519", group: wire.GroupX25519, expected: CategoryGood},
		{name: "secp256r1", group: wire.GroupSecp256r1, expected: CategoryGood},
		{name: "secp384r1", group: wire.GroupSecp384r1, expected: CategoryGood},
		{name: "secp224r1 is on its way out", group: 21, expected: CategoryPhaseOut},
		{name: "ffdhe2048 is on its way out", group: wire.GroupFfdhe2048, expected: CategoryPhaseOut},
		{name: "ffdhe4096 is still on its way out", group: wire.GroupFfdhe4096, expected: CategoryPhaseOut},
		{name: "an unknown group", group: 0xdead, expected: CategoryInsufficient},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := CategorizeGroup(testCase.group); got != testCase.expected {
				t.Errorf("CategorizeGroup(%s) = %q, want %q", GroupName(testCase.group), got, testCase.expected)
			}
		})
	}
}

func TestCategoryRankOrdersFromBestToWorst(t *testing.T) {
	t.Parallel()

	ordered := []Category{CategoryGood, CategorySufficient, CategoryPhaseOut, CategoryInsufficient}

	for index := 1; index < len(ordered); index++ {
		if ordered[index-1].Rank() >= ordered[index].Rank() {
			t.Errorf("%q does not rank before %q", ordered[index-1], ordered[index])
		}
	}
}

func TestName(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		id       uint16
		expected string
	}{
		{name: "a known suite", id: 0x1301, expected: "TLS_AES_128_GCM_SHA256"},
		{name: "an unknown suite falls back to its number", id: 0x00ab, expected: "unknown suite 0x00ab"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := Name(testCase.id); got != testCase.expected {
				t.Errorf("Name(%#04x) = %q, want %q", testCase.id, got, testCase.expected)
			}
		})
	}
}
