package model

import "errors"

var (
	ErrNotFound = errors.New("not found")
	ErrAmbiguous = errors.New("cannot identify accounts uniquely with this string")
	ErrDuplicateIdentifier = errors.New("identifier already used by another account for this service")
	ErrDuplicateField = errors.New("duplicate field name in account")
	ErrDuplicateID = errors.New("account ID already exists")
	ErrInvalidAccount = errors.New("invalid account")
)

