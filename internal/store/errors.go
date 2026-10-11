package store

import "errors"

var (
	ErrNotAVault          = errors.New("not a Rivest vault file")
	ErrUnsupportedVersion = errors.New("unsupported vault file version")
	ErrCorrupt            = errors.New("vault contents are damaged")
	ErrExists             = errors.New("a vault already exists at this path")
)
