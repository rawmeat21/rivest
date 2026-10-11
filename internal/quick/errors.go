package quick

import "errors"

var (
	ErrNoQuickUnlock = errors.New("quick unlock is not set up")
	ErrNeedSecret    = errors.New("this quick unlock needs a PIN, pattern or text")
	ErrWrongSecret   = errors.New("wrong unlock secret")
	ErrTooManyTries  = errors.New("too many wrong attempts: quick unlock was disabled, use the master password")
	ErrBadFile       = errors.New("quick-unlock file is damaged")
)
