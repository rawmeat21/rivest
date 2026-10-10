package model

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"time"
)

type Account struct {
	ID          string
	Service     string
	Identifiers []Identifier
	Fields      []Field
	Created     time.Time
	Updated     time.Time
}

func NewAccount(service string, identifiers []Identifier, fields []Field) (*Account, error) {

	// An account is created by this function

	service = NormalizeService(service)

	if service == "" {
		return nil, fmt.Errorf("%w: service cannot be empty", ErrInvalidAccount)
	}

	if len(identifiers) == 0 {
		return nil, fmt.Errorf("%w: at least one identifier is required", ErrInvalidAccount)
	}

	id, err := newID()

	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()

	return &Account{
		ID:          id,
		Service:     service,
		Identifiers: slices.Clone(identifiers),
		Fields:      slices.Clone(fields),
		Created:     now,
		Updated:     now,
	}, nil
}

func (a *Account) MainIdentifier() Identifier {

	if len(a.Identifiers) == 0 {
		return Identifier{}
	}

	return a.Identifiers[0]
}

func (a *Account) Field(name string) (Field, bool) {

	for _, field := range a.Fields {
		if strings.EqualFold(NormalizeField(field.Name), NormalizeField(name)) {
			return field, true
		}
	}

	return Field{}, false
}

func newID() (string, error) {
	b := make([]byte, 16)

	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	return hex.EncodeToString(b), nil
}
