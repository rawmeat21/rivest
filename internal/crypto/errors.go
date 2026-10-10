package crypto

import "errors"

var (
	ErrDecrypt   = errors.New("decryption failed: wrong key or damaged data")
	ErrBadParams = errors.New("invalid key-derivation settings")
	ErrBadInput  = errors.New("invalid input")
)
