package crypto

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)


// wrapped DEK=nonce+key+tag=24+32+16=72bytes
const WrappedDEKSize = chacha20poly1305.NonceSizeX + KeySize + chacha20poly1305.Overhead

func bodyKey(dek []byte) ([]byte, error) {

	if len(dek) != KeySize {
		return nil, fmt.Errorf("%w: DEK must be %d bytes", ErrBadInput, KeySize)
	}

	key := make([]byte, KeySize)
	reader := hkdf.New(sha256.New, dek, nil, []byte("rivest/body/v1"))

	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, err
	}
	
	return key, nil
}

func SealBody(dek, plaintext, aad []byte) ([]byte, error) {

	key, err := bodyKey(dek)
	if err != nil {
		return nil, err
	}

	defer clear(key)
	return seal(key, plaintext, aad)
}

func OpenBody(dek, sealed, aad []byte) ([]byte, error) {

	key, err := bodyKey(dek)
	if err != nil {
		return nil, err
	}
	
	defer clear(key)
	return open(key, sealed, aad)
}