package crypto

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// makes the private key for one field of one account
func fieldKey(dek []byte, accountID, fieldName string) ([]byte, error) {

	if len(dek) != KeySize {
		return nil, fmt.Errorf("%w: DEK must be %d bytes", ErrBadInput, KeySize)
	}

	if accountID == "" || fieldName == "" {
		return nil, fmt.Errorf("%w: account ID and field name are required", ErrBadInput)
	}

	info := "rivest/field/v1\x00" + accountID + "\x00" + fieldName

	key := make([]byte, KeySize)
	reader := hkdf.New(sha256.New, dek, nil, []byte(info))

	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, err
	}

	return key, nil
}

// label that pins a sealed value to its account and field name
func fieldAAD(accountID, fieldName string) []byte {

	return []byte(accountID + "\x00" + fieldName)
}

func SealField(dek []byte, accountID, fieldName string, plaintext []byte) ([]byte, error) {

	key, err := fieldKey(dek, accountID, fieldName) // generate key for the field name

	if err != nil {
		return nil, err
	}

	defer clear(key)

	return seal(key, plaintext, fieldAAD(accountID, fieldName))
}

func OpenField(dek []byte, accountID, fieldName string, sealed []byte) ([]byte, error) {

	key, err := fieldKey(dek, accountID, fieldName)
	if err != nil {
		return nil, err
	}

	defer clear(key)
	return open(key, sealed, fieldAAD(accountID, fieldName))
}
