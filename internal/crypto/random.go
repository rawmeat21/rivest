package crypto

import "crypto/rand"

const (
	KeySize       = 32
	SaltSize      = 16
	SecretKeySize = 16
)

func randomBytes(n int) ([]byte, error) {

	// returns n byte random string (or n random uint8 values)

	b := make([]byte, n)

	if _, err := rand.Read(b); err != nil {
		return nil, err
	}

	return b, nil
}

// DEK is just 32 random uint8 values
func NewDEK() ([]byte, error) {
	return randomBytes(KeySize)
}

// A salt makes our password produce a different key
// than the same password in someone else’s vault, so an attacker can’t prepare guesses in advance
func NewSalt() ([]byte, error) {
	return randomBytes(SaltSize)
}

// makes a stolen file very hard to crack even if the master password is weak
// our secret key is just 16 random 8 bit integers
func NewSecretKey() ([]byte, error) {
	return randomBytes(SecretKeySize)
}

func Wipe(b []byte) {
	clear(b)
}
