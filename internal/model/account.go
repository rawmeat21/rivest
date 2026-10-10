package model

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"slices"
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

	fields = slices.Clone(fields) // must clone the outer array first
	for idx := range fields {
		fields[idx].Value = slices.Clone(fields[idx].Value)
	}

	return &Account{
		ID:          id,
		Service:     service,
		Identifiers: slices.Clone(identifiers),
		Fields:      fields,
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

	i := a.indexOfField(name)
	if i == -1 {
		return Field{}, false
	}

	f := a.Fields[i]
	f.Value = slices.Clone(f.Value)
	return f, true

}

func newID() (string, error) {
	b := make([]byte, 16)

	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	return hex.EncodeToString(b), nil
}

func (a *Account) indexOfIdentifier(i Identifier) int {
	return slices.IndexFunc(a.Identifiers, func(ident Identifier) bool {
		return ident.Kind == i.Kind && i.Key() == ident.Key()
	})
}

func (a *Account) AddIdentifier(i Identifier) error {

	if i.Kind == "" || i.Key() == "" {
		return fmt.Errorf("%w: identifier kind and value cannot be empty", ErrInvalidAccount)
	}

	index := a.indexOfIdentifier(i)

	if index != -1 {
		return fmt.Errorf("%w: %s", ErrDuplicateIdentifier, i.Value)
	}

	a.Identifiers = append(a.Identifiers, i)
	return nil
}

func (a *Account) RemoveIdentifier(i Identifier) error {

	index := a.indexOfIdentifier(i)

	if index != -1 {
		a.Identifiers = slices.Delete(a.Identifiers, index, index+1)
		return nil
	} else {
		return fmt.Errorf("%w: identifier %s", ErrNotFound, i.Value)
	}
}

func (a *Account) SetIdentifier(kind IdentifierKind, oldValue string, newValue string) error {

	old := NewIdentifier(kind, oldValue)
	new := NewIdentifier(kind, newValue)

	if kind == "" || old.Key() == "" || new.Key() == "" {
		return fmt.Errorf("%w: identifier kind and values cannot be empty", ErrInvalidAccount)
	}

	index := a.indexOfIdentifier(old)

	if index == -1 {
		return fmt.Errorf("%w: identifier %s", ErrNotFound, oldValue)
	}

	if j := a.indexOfIdentifier(new); j != -1 && j != index {
		return fmt.Errorf("%w: %s", ErrDuplicateIdentifier, newValue)
	}

	a.Identifiers[index] = new
	return nil
}

func (a *Account) SetService(name string) error {
	name = NormalizeService(name)
	if name == "" {
		return fmt.Errorf("%w: service name cannot be empty", ErrInvalidAccount)
	}

	a.Service = name
	return nil
}

func (a *Account) indexOfField(name string) int {
	n := NormalizeField(name)
	return slices.IndexFunc(a.Fields, func(f Field) bool {
		return NormalizeField(f.Name) == n
	})
}

func (a *Account) AddField(f Field) error {
	if NormalizeField(f.Name) == "" {
		return fmt.Errorf("%w: field name cannot be empty", ErrInvalidAccount)
	}

	if a.indexOfField(f.Name) != -1 {
		return fmt.Errorf("%w: %s", ErrDuplicateField, f.Name)
	}

	f.Value = slices.Clone(f.Value) // this makes f.Value point to a new byte array, which is clone of the previous one
	// why clone? - so that the caller can't modify the array pointed by f.Value and corrupt the data from outside

	a.Fields = append(a.Fields, f)
	return nil
}

func (a *Account) RemoveField(name string) error {
	i := a.indexOfField(name)

	if i == -1 {
		return fmt.Errorf("%w: field %s", ErrNotFound, name)
	}

	clear(a.Fields[i].Value)
	a.Fields = slices.Delete(a.Fields, i, i+1)
	return nil
}

func (a *Account) SetField(name string, value []byte, isEncrypted bool) error {
	i := a.indexOfField(name)
	if i == -1 {
		return fmt.Errorf("%w: field %s", ErrNotFound, name)
	}

	newValue := slices.Clone(value)
	clear(a.Fields[i].Value)
	a.Fields[i].Value = newValue
	a.Fields[i].IsEncrypted = isEncrypted
	return nil
}

func (a *Account) RenameField(oldName string, newName string) error {

	if NormalizeField(newName) == "" {
		return fmt.Errorf("%w: field name cannot be empty", ErrInvalidAccount)
	}

	i := a.indexOfField(oldName)

	if i == -1 {
		return fmt.Errorf("%w: field %s", ErrNotFound, oldName)
	}

	if j := a.indexOfField(newName); j != -1 && j != i {
		return fmt.Errorf("%w: %s", ErrDuplicateField, newName)
	}

	a.Fields[i].Name = newName
	return nil
}

func (a *Account) clone() *Account {
	c := *a
	c.Identifiers = slices.Clone(a.Identifiers)
	c.Fields = slices.Clone(a.Fields)

	for idx := range c.Fields {
		c.Fields[idx].Value = slices.Clone(c.Fields[idx].Value)
	}

	return &c
}

func (a *Account) wipe() {
	for idx := range a.Fields {
		clear(a.Fields[idx].Value)
	}
}
