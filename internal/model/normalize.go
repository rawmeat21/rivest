package model

import (
	"slices"
	"strings"
)

var allKinds = []IdentifierKind{KindEmail, KindPhone, KindUsername, KindCustom}

/*

service - normalised to lower case, with single space separated values
identifer - emails and usernames are lowercased, phone numbers get replaced by the subsequence of their digits, custom is unchanged
*/

func NormalizeService(service string) string {
	// .Fields is basically split
	return strings.Join(strings.Fields(strings.ToLower(service)), " ")
}

func NormalizeIdentifier(kind IdentifierKind, value string) string {
	v := strings.TrimSpace(value)

	switch kind {
	case KindEmail, KindUsername:
		return strings.ToLower(v)
	case KindPhone:
		return digitsOnly(v)
	default:
		return v
	}
}

func NormalizeSearch(identifierValue string) []string {
	v := strings.TrimSpace(identifierValue)

	var keys []string

	for _, kind := range allKinds {
		if kind == KindPhone && !looksLikePhone(v) {
			continue
		}

		key := NormalizeIdentifier(kind, v)

		if key != "" && !slices.Contains(keys, key) {
			keys = append(keys, key)
		}
	}

	return keys
}

func NormalizeField(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

func looksLikePhone(s string) bool {
	digits := 0
	for _, r := range s {
		if '0' <= r && r <= '9' {
			digits++
		} else if strings.ContainsRune("+-(). ", r) {
			continue
		} else {
			return false
		}
	}

	return digits > 0
}

func digitsOnly(s string) string {
	var b strings.Builder
	for _, r := range s {
		if '0' <= r && r <= '9' {
			b.WriteRune(r)
		}
	}

	return b.String()
}
