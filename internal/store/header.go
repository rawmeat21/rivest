package store

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/rawmeat21/rivest/internal/crypto"
)

const (
	formatVersion = 1
	headerLen     = 113 
	prefixLen     = 33
)

var magic = [6]byte{'R', 'I', 'V', 'E', 'S', 'T'}

type Header struct {
	Magic      [6]byte
	Version    uint16
	Time       uint32 
	MemoryKiB  uint32
	Threads    uint8
	Salt       [crypto.SaltSize]byte
	WrappedDEK [crypto.WrappedDEKSize]byte
	Counter    uint64
}

func init() {
	// stop at startup if header size and header length don't match
	if binary.Size(Header{}) != headerLen {
		panic("store: headerLen does not match the Header struct")
	}
}

func newHeader(p crypto.KDFParams, salt []byte) Header {

	h := Header{
		Magic:     magic,
		Version:   formatVersion,
		Time:      p.Time,
		MemoryKiB: p.MemoryKiB,
		Threads:   p.Threads,
	}

	copy(h.Salt[:], salt)

	return h
}

func (h *Header) params() crypto.KDFParams {

	return crypto.KDFParams{Time: h.Time, MemoryKiB: h.MemoryKiB, Threads: h.Threads}

}

func (h *Header) marshal() []byte {

	// convert header -> 113bytes binary
	var buf bytes.Buffer

	if err := binary.Write(&buf, binary.BigEndian, h); err != nil {
		panic(err) 
	}

	return buf.Bytes()
}

func parseHeader(data []byte) (*Header, error) {

	if len(data) < headerLen {
		return nil, ErrNotAVault
	}

	var h Header

	if err := binary.Read(bytes.NewReader(data[:headerLen]), binary.BigEndian, &h); err != nil {
		return nil, ErrNotAVault
	}

	if h.Magic != magic {
		return nil, ErrNotAVault
	}

	if h.Version != formatVersion {
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedVersion, h.Version)
	}

	if err := h.params().Validate(); err != nil {
		return nil, err
	}

	return &h, nil
}

