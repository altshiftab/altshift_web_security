package wire

import (
	"encoding/binary"
	"fmt"

	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
)

// Reader reads the big-endian integers and length-prefixed blocks TLS is made of.
//
// Every field in every message this package parses goes through it. TLS is almost
// entirely nested length prefixes, and open-coding the slice arithmetic at each one
// is where the off-by-one bugs live: a reader that refuses to read past its end,
// and that hands back a sub-reader bounded by the prefix it just read, makes the
// nesting structural rather than something each parser has to get right again.
type Reader struct {
	data []byte
}

func NewReader(data []byte) *Reader {
	return &Reader{data: data}
}

// Len is what remains unread.
func (reader *Reader) Len() int {
	if reader == nil {
		return 0
	}

	return len(reader.data)
}

func (reader *Reader) Empty() bool {
	return reader.Len() == 0
}

// Rest hands back everything unread, and leaves the reader empty.
func (reader *Reader) Rest() []byte {
	if reader == nil {
		return nil
	}

	rest := reader.data
	reader.data = nil

	return rest
}

func (reader *Reader) Bytes(count int) ([]byte, error) {
	if reader == nil {
		return nil, altshiftErrors.NewWithTrace(errTruncated(count, 0))
	}

	if count < 0 || len(reader.data) < count {
		return nil, altshiftErrors.NewWithTrace(errTruncated(count, len(reader.data)))
	}

	taken := reader.data[:count]
	reader.data = reader.data[count:]

	return taken, nil
}

func (reader *Reader) Uint8() (uint8, error) {
	taken, err := reader.Bytes(1)
	if err != nil {
		return 0, fmt.Errorf("bytes: %w", err)
	}

	return taken[0], nil
}

func (reader *Reader) Uint16() (uint16, error) {
	taken, err := reader.Bytes(2)
	if err != nil {
		return 0, fmt.Errorf("bytes: %w", err)
	}

	return binary.BigEndian.Uint16(taken), nil
}

func (reader *Reader) Uint24() (uint32, error) {
	taken, err := reader.Bytes(3)
	if err != nil {
		return 0, fmt.Errorf("bytes: %w", err)
	}

	return uint32(taken[0])<<16 | uint32(taken[1])<<8 | uint32(taken[2]), nil
}

func (reader *Reader) Uint32() (uint32, error) {
	taken, err := reader.Bytes(4)
	if err != nil {
		return 0, fmt.Errorf("bytes: %w", err)
	}

	return binary.BigEndian.Uint32(taken), nil
}

// Uint8LengthPrefixed and its wider siblings read a length and return a reader over
// exactly that many bytes, so what follows the block cannot be read out of it by
// mistake.
func (reader *Reader) Uint8LengthPrefixed() (*Reader, error) {
	length, err := reader.Uint8()
	if err != nil {
		return nil, fmt.Errorf("uint8: %w", err)
	}

	return reader.subReader(int(length))
}

func (reader *Reader) Uint16LengthPrefixed() (*Reader, error) {
	length, err := reader.Uint16()
	if err != nil {
		return nil, fmt.Errorf("uint16: %w", err)
	}

	return reader.subReader(int(length))
}

func (reader *Reader) Uint24LengthPrefixed() (*Reader, error) {
	length, err := reader.Uint24()
	if err != nil {
		return nil, fmt.Errorf("uint24: %w", err)
	}

	return reader.subReader(int(length))
}

func (reader *Reader) subReader(length int) (*Reader, error) {
	taken, err := reader.Bytes(length)
	if err != nil {
		return nil, fmt.Errorf("bytes: %w", err)
	}

	return NewReader(taken), nil
}

// Uint16List reads the whole reader as a sequence of uint16, which is the shape of
// a cipher suite list, a group list and a signature algorithm list alike.
func (reader *Reader) Uint16List() ([]uint16, error) {
	if reader == nil {
		return nil, nil
	}

	if reader.Len()%2 != 0 {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: a list of uint16 has an odd length", altshiftErrors.ErrParseError),
			reader.Len(),
		)
	}

	values := make([]uint16, 0, reader.Len()/2)
	for !reader.Empty() {
		value, err := reader.Uint16()
		if err != nil {
			return nil, fmt.Errorf("uint16: %w", err)
		}

		values = append(values, value)
	}

	return values, nil
}

func errTruncated(wanted int, available int) error {
	return fmt.Errorf(
		"%w: %d bytes were wanted and %d remain",
		altshiftErrors.ErrParseError,
		wanted,
		available,
	)
}
