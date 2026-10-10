package crypto

import (
	"bytes"
	"errors"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	// returns the slice, stops the test if there was an error
	must := func(b []byte, err error) []byte {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	fast := KDFParams{Time: 1, MemoryKiB: 8 * 1024, Threads: 1} // small settings: quick test
	salt, secret, dek := must(NewSalt()), must(NewSecretKey()), must(NewDEK())
	header := []byte("pretend header")

	kek := must(DeriveKEK([]byte("correct horse"), secret, salt, fast))
	wrapped := must(WrapDEK(kek, dek, header))

	again := must(DeriveKEK([]byte("correct horse"), secret, salt, fast))
	if got := must(UnwrapDEK(again, wrapped, header)); !bytes.Equal(got, dek) {
		t.Fatal("DEK did not survive the round trip")
	}

	wrong := must(DeriveKEK([]byte("wrong horse"), secret, salt, fast))
	if _, err := UnwrapDEK(wrong, wrapped, header); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("wrong password: got %v, want ErrDecrypt", err)
	}

	sealed := must(SealField(dek, "acc1", "password", []byte("hunter2")))
	if got := must(OpenField(dek, "acc1", "password", sealed)); string(got) != "hunter2" {
		t.Fatal("field did not survive the round trip")
	}
	if _, err := OpenField(dek, "acc1", "pin", sealed); !errors.Is(err, ErrDecrypt) {
		t.Fatal("a sealed field opened under the wrong name")
	}
}
