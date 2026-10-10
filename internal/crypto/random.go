package crypto

import "crypto/rand"

const (
	KeySize       = 32
	SaltSize      = 16
	SecretKeySize = 16
)

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)

	if _, err := rand.Read(b); err != nil {
		return nil, err
	}

	return b, nil
}

func NewDEK() ([]byte, error) {
	return randomBytes(KeySize)
}

// A salt makes our password produce a different key
// than the same password in someone else’s vault, so an attacker can’t prepare guesses in advance.
func NewSalt() ([]byte, error) {
	return randomBytes(SaltSize)
}

// makes a stolen file very hard to crack even if the master password is weak
func NewSecretKey() ([]byte, error) {
	return randomBytes(SecretKeySize)
}

func Wipe(b []byte) {
	clear(b)
}
