package crypto

import "fmt"

// WrapDEK locks the DEK with the KEK. aad should be the file header bytes.
func WrapDEK(kek, dek, aad []byte) ([]byte, error) {

	if len(dek) != KeySize {
		return nil, fmt.Errorf("%w: DEK must be %d bytes", ErrBadInput, KeySize)
	}

	return seal(kek, dek, aad)
}

func UnwrapDEK(kek, wrapped, aad []byte) ([]byte, error) {
	dek, err := open(kek, wrapped, aad)

	if err != nil {
		return nil, err
	}

	if len(dek) != KeySize {
		Wipe(dek)
		return nil, ErrDecrypt
	}

	return dek, nil
}
