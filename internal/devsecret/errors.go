package devsecret

import "errors"

var (
	ErrNotFound    = errors.New("device secret not found")
	ErrUnavailable = errors.New("device secret store is not available")
)
