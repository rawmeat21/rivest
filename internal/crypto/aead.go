package crypto

// authenticated encryption

/*
scrambles the data and attaches a tag

The tag is a fingerprint that only someone with the right key can produce.
When opening, if the key is wrong or tampered with, the tag doesn’t match and opening fails.

*/

import (
	"crypto/cipher"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

func newAEAD(key []byte) (cipher.AEAD, error) {

	if len(key) != KeySize {
		return nil, fmt.Errorf("%w: key must be %d bytes", ErrBadInput, KeySize)
	}

	return chacha20poly1305.NewX(key)
}

// seal locks plaintext. Result: nonce, scrambled data, tag
func seal(key, plaintext, aad []byte) ([]byte, error) {
	aead, err := newAEAD(key)

	if err != nil {
		return nil, err
	}

	/*

		nonce is 24 random bytes made for every locking.
		It ensures that locking the same secret twice gives different results.
		The same key and nonce must never be reused.

	*/

	nonce, err := randomBytes(aead.NonceSize())

	if err != nil {
		return nil, err
	}

	out := make([]byte, 0, len(nonce)+len(plaintext)+aead.Overhead())
	out = append(out, nonce...) // basically out+=nonce

	return aead.Seal(out, nonce, plaintext, aad), nil
}

// open() unlocks what seal() 's output
func open(key, sealed, aad []byte) ([]byte, error) {

	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}

	if len(sealed) < aead.NonceSize()+aead.Overhead() {
		return nil, ErrDecrypt
	}

	nonce := sealed[:aead.NonceSize()] // get nonce
	ciphertext := sealed[aead.NonceSize():]

	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrDecrypt
	}

	return plaintext, nil
}
