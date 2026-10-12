package gate

import (
	"errors"
	"fmt"
	"time"
)

var (
	ErrRequired  = errors.New("gate: check required")
	ErrWrong     = errors.New("gate: wrong secret")
	ErrLocked    = errors.New("gate: too many wrong attempts")
	ErrBadMethod = errors.New("gate: unknown or unsupported method")
	ErrBadSecret = errors.New("gate: secret does not fit the method")
	ErrBadConfig = errors.New("gate: damaged gate settings")
	ErrBadPolicy = errors.New("gate: invalid policy")
)

// LockedError says how long the caller must wait
// errors.As gives the wait time
type LockedError struct {
	Remaining time.Duration
}

func (e *LockedError) Error() string {
	return fmt.Sprintf("%v: try again in %s", ErrLocked, e.Remaining.Round(time.Second))
}

func (e *LockedError) Unwrap() error {
	return ErrLocked 
}