package crypto

import (
	"crypto/sha256"
	"fmt"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
	"io"
)

// key derivation function

type KDFParams struct {
	Time      uint32 // how many passes over the memory
	MemoryKiB uint32 // how much memory to use
	Threads   uint8  // how many cpu threads to use
}

var DefaultKDFParams = KDFParams{Time: 3, MemoryKiB: 64 * 1024, Threads: 4}

func (p KDFParams) Validate() error {
	if p.Time < 1 || p.Time > 10 {
		return fmt.Errorf("%w: time must be between 1 and 10", ErrBadParams)
	}

	if p.MemoryKiB < 8*1024 || p.MemoryKiB > 512*1024 {
		return fmt.Errorf("%w: memory must be between 8 MiB and 512 MiB", ErrBadParams)
	}

	if p.Threads < 1 || p.Threads > 16 {
		return fmt.Errorf("%w: threads must be between 1 and 16", ErrBadParams)
	}
	return nil
}

func DeriveKEK(password, secretKey, salt []byte, p KDFParams) ([]byte, error) {

	/*
		this will give us the KEK (key encryption key)
		this key's only job is to lock and unlock the DEK
		the DEK is encrypted with the KEK, this gives us the wrapped DEK
		hkdf(argon2id(password)+secretKey) = kek
	*/

	/*
		pass in the master password in password field
	*/

	if err := p.Validate(); err != nil {
		return nil, err
	}

	if len(password) == 0 {
		return nil, fmt.Errorf("%w: empty password", ErrBadInput)
	}

	/*
		SecretKeySize and SaltSize are 16
	*/

	if len(secretKey) != SecretKeySize || len(salt) != SaltSize {
		return nil, fmt.Errorf("%w: wrong secret key or salt length", ErrBadInput)
	}

	// password -> 32byte key using KDF
	pwKey := argon2.IDKey(password, salt, p.Time, p.MemoryKiB, p.Threads, KeySize)
	defer clear(pwKey)

	// mixed = pwKey+secretKey (concat) (32+16=48bytes)
	mixed := make([]byte, 0, len(pwKey)+len(secretKey))
	mixed = append(mixed, pwKey...)
	mixed = append(mixed, secretKey...)
	defer clear(mixed)

	kek := make([]byte, KeySize) // kek is 32bytes

	// kek = hkdf(mixed+label "rivest/kek/v1")
	// sha256 is the scrambling function
	reader := hkdf.New(sha256.New, mixed, nil, []byte("rivest/kek/v1"))

	if _, err := io.ReadFull(reader, kek); err != nil {
		return nil, err
	}

	return kek, nil
}
