package gate

import "fmt"

/*

The app prompts the user for a special password before they can see the field

none -> no check
device -> the device login (can be a fingerprint / pattern / PIN etc.). The frontend has to verify this,
after which it calls ConfirmDevice
PIN -> can be 4 to 16 digits
pattern -> 3x3 grid, numbering is 0-8. A pattern is an ordered list of points on a grid
text -> any special text, 6 to 128 characters allowed

*/

type Method string

const (
	MethodNone    Method = "none"
	MethodDevice  Method = "device"
	MethodPIN     Method = "pin"
	MethodPattern Method = "pattern"
	MethodText    Method = "text"
)

const (
	MinPIN         = 4
	MaxPIN         = 16
	MinPatternDots = 4
	MaxPatternDots = 9
	MinText        = 6
	MaxText        = 128
)

func (m Method) hasSecret() bool {
	// none and device login cannot have any secrets

	return m == MethodPIN || m == MethodPattern || m == MethodText
}

func Encode(m Method, secret string) ([]byte, error) {
	// encodes secret into bytes

	switch m {
	case MethodPIN:
		if len(secret) < MinPIN || len(secret) > MaxPIN || !onlyBetween(secret, '0', '9') {
			return nil, fmt.Errorf("%w: a PIN should be between %d to %d digits", ErrBadSecret, MinPIN, MaxPIN)
		}
	case MethodPattern:
		if len(secret) < MinPatternDots || len(secret)> MaxPatternDots || !onlyBetween(secret, '0', '8') || hasRepeat(secret) {
			return nil, fmt.Errorf("%w: a pattern joins %d to %d different dots", ErrBadSecret, MinPatternDots, MaxPatternDots)
		}
	case MethodText:
		if len(secret) < MinText || len(secret)> MaxText {
			return nil, fmt.Errorf("%w: text is %d to %d bytes", ErrBadSecret, MinText, MaxText)
		}
	default:
		return nil, fmt.Errorf("%w: %q", ErrBadMethod, string(m))
	}

	return []byte(string(m) + "\x00" + secret), nil
}

func onlyBetween(s string, lo, hi byte) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < lo || s[i] > hi {
			return false
		}
	}
	return true
}
 
func hasRepeat(s string) bool {
	var seen [256]bool
	for i := 0; i < len(s); i++ {
		if seen[s[i]] {
			return true
		}
		seen[s[i]] = true
	}
	return false
}
