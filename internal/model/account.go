package model

import "time"

type Account struct {
	ID          string
	Service     string
	Identifiers []Identifier
	Fields      []Field
	Created     time.Time
	Updated     time.Time
}

func (a *Account) MainIdentifier() Identifier
func (a *Account) Field(name string) (Field, bool)
