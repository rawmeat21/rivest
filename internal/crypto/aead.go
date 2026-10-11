package crypto

// authenticated encryption with associated data

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

// seal locks plaintext
func seal(key, plaintext, aad []byte) ([]byte, error) {

	/*
		output=nonce+scrambled plaintext+tag=24+x+16=40+x bytes (x = number of bytes in plaintext)
	*/

	aead, err := newAEAD(key)

	if err != nil {
		return nil, err
	}

	/*
		nonce is 24 random bytes made for every locking.
		It ensures that locking the same secret twice gives different results.
		The same key and nonce must never be reused.
	*/

	nonce, err := RandomBytes(aead.NonceSize()) // aead.NonceSize() will return 24 for ChaCha20-Poly1305

	if err != nil {
		return nil, err
	}
	// aead.Overhead() should be 16 = tag size
	out := make([]byte, 0, len(nonce)+len(plaintext)+aead.Overhead())
	out = append(out, nonce...) // basically out=nonce

	// (key, nonce, plaintext, aad) -> |nonce|ciphertext|tag|

	return aead.Seal(out, nonce, plaintext, aad), nil
}

// open() unlocks seal()'s output
func open(key, sealed, aad []byte) ([]byte, error) {

	// the aad and key need to be the same

	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}

	if len(sealed) < aead.NonceSize()+aead.Overhead() {
		return nil, ErrDecrypt
	}

	nonce := sealed[:aead.NonceSize()]      // get nonce by reading the first 24 bytes
	ciphertext := sealed[aead.NonceSize():] // this is technically ciphertext+tag

	// (key, nonce, ciphertext+tag, aad) -> plaintext (x bytes)
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)

	if err != nil {

		/*
			could mean: bad nonce, bad key, bad aad, etc.
		*/

		return nil, ErrDecrypt
	}

	return plaintext, nil
}
