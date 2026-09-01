package probe

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"strings"

	"github.com/altshiftab/altshift_web_security/pkg/tls/observation"
	"github.com/altshiftab/altshift_web_security/pkg/tls/wire"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
)

// Whether a server offers 0-RTT is stated in the session ticket, in an early_data
// extension carrying the largest early data it will accept. Under TLS 1.3 the ticket
// arrives after the handshake and so under encryption, and crypto/tls exposes
// neither the ticket's extensions nor the keys to read them.
//
// It does expose the traffic secrets, through KeyLogWriter, and the connection can
// be wrapped to keep the bytes. That is enough: the records are opened here with the
// same key schedule the library used, and the ticket read out of them. Nothing is
// forged and no security decision rests on it -- this decrypts a stream it was
// already a party to, in order to read a field the API does not surface.
//
// Note that SessionState.EarlyData is not the answer. crypto/tls sets it only for
// QUIC connections, so over TCP it is false whatever the server advertised.

// parseKeyLog reads the NSS key log format crypto/tls writes: a label, the client
// random, and the secret, space separated, one per line.
func parseKeyLog(log string) map[string][]byte {
	secrets := map[string][]byte{}

	for _, line := range strings.Split(log, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 {
			continue
		}

		secret, err := hex.DecodeString(fields[2])
		if err != nil {
			continue
		}

		secrets[fields[0]] = secret
	}

	return secrets
}

// expandLabel is HKDF-Expand-Label from RFC 8446 section 7.1.
func expandLabel(newHash func() hash.Hash, secret []byte, label string, length int) ([]byte, error) {
	full := "tls13 " + label

	// Both lengths are written into fixed-width fields. Every caller here passes a
	// key or nonce size and a label of a few characters, so this is a guard on the
	// callers rather than on the input.
	if length < 0 || length > 0xffff || len(full) > 0xff {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: a label or length does not fit its field", altshiftErrors.ErrValidationError),
			length,
			len(full),
		)
	}

	var info []byte
	info = binary.BigEndian.AppendUint16(info, uint16(length))

	info = append(info, byte(len(full)&0xff))
	info = append(info, full...)
	// An empty context, which is what the key and iv derivations use.
	info = append(info, 0)

	expanded, err := hkdf.Expand(newHash, secret, string(info), length)
	if err != nil {
		return nil, err
	}

	return expanded, nil
}

// epoch is one set of record protection keys, and the sequence number that walks
// them. A TLS 1.3 connection has two on the server's side: the handshake keys, and
// the application keys that take over after Finished.
type epoch struct {
	aead cipher.AEAD
	iv   []byte
	seq  uint64
}

func newEpoch(cipherSuite uint16, secret []byte) *epoch {
	var newHash func() hash.Hash
	var keyLength int

	switch cipherSuite {
	case tls.TLS_AES_128_GCM_SHA256:
		newHash = func() hash.Hash { return sha256.New() }
		keyLength = 16
	case tls.TLS_AES_256_GCM_SHA384:
		newHash = func() hash.Hash { return sha512.New384() }
		keyLength = 32
	default:
		// ChaCha20-Poly1305 is not in the standard library as an AEAD this can
		// build, and hand-rolling a stream cipher to read one optional field
		// would be a poor trade. The check reports itself undetermined instead.
		return nil
	}

	key, err := expandLabel(newHash, secret, "key", keyLength)
	if err != nil {
		return nil
	}

	iv, err := expandLabel(newHash, secret, "iv", 12)
	if err != nil {
		return nil
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil
	}

	return &epoch{aead: aead, iv: iv}
}

// open decrypts one record and returns its contents and its real content type, which
// TLS 1.3 hides inside the ciphertext behind any padding.
func (epoch *epoch) open(header []byte, payload []byte) ([]byte, uint8, bool) {
	nonce := make([]byte, len(epoch.iv))
	copy(nonce, epoch.iv)

	var sequence [8]byte
	binary.BigEndian.PutUint64(sequence[:], epoch.seq)

	for index := range sequence {
		nonce[len(nonce)-8+index] ^= sequence[index]
	}

	plaintext, err := epoch.aead.Open(nil, nonce, payload, header)
	if err != nil {
		return nil, 0, false
	}

	epoch.seq++

	// The content type is the last non-zero byte; everything after it is padding.
	for index := len(plaintext) - 1; index >= 0; index-- {
		if plaintext[index] != 0 {
			return plaintext[:index], plaintext[index], true
		}
	}

	return nil, 0, false
}

// inspectEarlyData reads the server's recorded byte stream and reports what its
// session ticket says about 0-RTT.
//
// It is a pure function of bytes and secrets, so a test builds the stream rather
// than needing a server that offers early data -- which is just as well, since Go's
// own server will not.
func inspectEarlyData(stream []byte, secrets map[string][]byte, cipherSuite uint16) *observation.EarlyData {
	handshakeSecret := secrets["SERVER_HANDSHAKE_TRAFFIC_SECRET"]
	applicationSecret := secrets["SERVER_TRAFFIC_SECRET_0"]

	if handshakeSecret == nil || applicationSecret == nil {
		return &observation.EarlyData{
			Reason: "the connection's traffic secrets were not available",
		}
	}

	handshakeEpoch := newEpoch(cipherSuite, handshakeSecret)
	applicationEpoch := newEpoch(cipherSuite, applicationSecret)

	if handshakeEpoch == nil || applicationEpoch == nil {
		return &observation.EarlyData{
			Reason: "the negotiated cipher suite is not one whose records this can open",
		}
	}

	current := handshakeEpoch
	switched := false

	for _, record := range wire.SplitRecords(stream) {
		if record[0] != wire.RecordTypeApplicationData {
			continue
		}

		plaintext, contentType, ok := current.open(record[:5], record[5:])
		if !ok {
			// The epoch changes at Finished. A record that will not open under
			// the handshake keys is the first one under the application keys,
			// whose sequence number starts again at zero.
			if switched {
				return &observation.EarlyData{
					Reason: "a record could not be opened after the key change",
				}
			}

			switched = true
			current = applicationEpoch

			plaintext, contentType, ok = current.open(record[:5], record[5:])
			if !ok {
				return &observation.EarlyData{
					Reason: "the first record after the key change could not be opened",
				}
			}
		}

		if contentType != wire.RecordTypeHandshake {
			continue
		}

		for _, message := range wire.SplitHandshake(plaintext) {
			if message.Type == wire.HandshakeTypeFinished && !switched {
				switched = true
				current = applicationEpoch
			}

			if message.Type != wire.HandshakeTypeNewSessionTicket {
				continue
			}

			maxSize, found := earlyDataFromTicket(message.Body)
			if !found {
				continue
			}

			// A ticket with the extension and a size of zero is not an offer.
			if maxSize == 0 {
				return &observation.EarlyData{Determined: true}
			}

			size := maxSize

			return &observation.EarlyData{Determined: true, MaxSize: &size}
		}
	}

	if switched {
		// The connection was read to the end and no ticket carried the extension.
		return &observation.EarlyData{Determined: true}
	}

	return &observation.EarlyData{Reason: "the server sent no session ticket this could read"}
}

// earlyDataFromTicket reads the early_data extension out of a NewSessionTicket.
// RFC 8446 section 4.6.1.
func earlyDataFromTicket(body []byte) (uint32, bool) {
	reader := wire.NewReader(body)

	// ticket_lifetime and ticket_age_add.
	if _, err := reader.Uint32(); err != nil {
		return 0, false
	}

	if _, err := reader.Uint32(); err != nil {
		return 0, false
	}

	if _, err := reader.Uint8LengthPrefixed(); err != nil {
		return 0, false
	}

	if _, err := reader.Uint16LengthPrefixed(); err != nil {
		return 0, false
	}

	extensions, err := reader.Uint16LengthPrefixed()
	if err != nil {
		return 0, false
	}

	for !extensions.Empty() {
		extensionType, err := extensions.Uint16()
		if err != nil {
			return 0, false
		}

		data, err := extensions.Uint16LengthPrefixed()
		if err != nil {
			return 0, false
		}

		if extensionType != wire.ExtensionEarlyData {
			continue
		}

		maxSize, err := data.Uint32()
		if err != nil {
			return 0, false
		}

		return maxSize, true
	}

	return 0, false
}
