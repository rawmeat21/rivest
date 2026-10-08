package model

/*

Identifiers identify an account. For example, common
identifiers are email, phone numbers, usernames, etc.

An Identifier must have the following property: For 1 service, 2 different accounts must have different Identifiers!

These are usually the fields one uses when logging into their account.

*/

type IdentifierKind string

const (
	KindEmail IdentifierKind = "email"
	KindPhone IdentifierKind = "phone"
	KindUsername IdentifierKind = "username"
	KindCustom IdentifierKind = "custom"
)

type Identifier struct {
	Kind  IdentifierKind // kind of identifier: can be email, phone number, username or custom identifier
	Value string         // value of the identifier
}

func (i Identifier) Key() string{
	// should return the value and kind of identifier
	return NormalizeIdentifier(i.Kind, i.Value)
}
