package crypto

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

func DeriveQuickKey(unlock []byte, deviceSecret []byte, salt []byte, p KDFParams) ([]byte, error) {
	// creates a quick key, a key which can be used for quick logins
	// this key is responsible for encrypting and decrypting the DEK

	if err := p.Validate(); err != nil {
		return nil, err
	}

	if len(deviceSecret) != KeySize || len(salt) != SaltSize {
		return nil, fmt.Errorf("%w: wrong device secret or salt length", ErrBadInput)
	}

	mixed := make([]byte, 0, 2*KeySize)

	if len(unlock) > 0 {
		slow := argon2.IDKey(unlock, salt, p.Time, p.MemoryKiB, p.Threads, KeySize) // 32bytes
		mixed = append(mixed, slow...)
		clear(slow)
	}
	mixed = append(mixed, deviceSecret...)
	defer clear(deviceSecret)

	key := make([]byte, KeySize)

	// mixed = |unlock password hkdf key|device secret| or mixed = |device secret|
	reader := hkdf.New(sha256.New, mixed, nil, []byte("rivest/quick/v1")) // 32 byte key

	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, err
	}

	return key, nil
}
