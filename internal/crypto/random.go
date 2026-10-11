package crypto

import "crypto/rand"

const (
	KeySize       = 32
	SaltSize      = 16
	SecretKeySize = 16
)

func RandomBytes(n int) ([]byte, error) {

	// returns n byte random string (or n random uint8 values)

	b := make([]byte, n)
	rand.Read(b) // according to go documentation, no handling errors is required
	return b, nil
}

// DEK is just 32 random uint8 values
func NewDEK() ([]byte, error) {
	return RandomBytes(KeySize)
}

// A salt makes our password produce a different key
// than the same password in someone else’s vault, so an attacker can’t prepare guesses in advance
// salt is 16bytes
func NewSalt() ([]byte, error) {
	return RandomBytes(SaltSize)
}

// makes a stolen file very hard to crack even if the master password is weak
// our secret key is just 16 random 8 bit integers
// secure key is 16bytes
func NewSecretKey() ([]byte, error) {
	return RandomBytes(SecretKeySize)
}

func Wipe(b []byte) {
	clear(b)
}