package devsecret

import (
	"fmt"
	"path/filepath"

	"github.com/rawmeat21/rivest/internal/crypto"
	"github.com/zalando/go-keyring"
)

const Size = 32

const (
	// these denote which Backend service is being used to store the device secret, an OS keyring or a file
	BackendKeyring uint8 = 1
	BackendFile    uint8 = 2

	BackendPlatform uint8 = 3
)

// provides a backend service to
type Provider interface {
	Backend() uint8
	Load() ([]byte, error)
	Save(secret []byte) error
	Delete() error
}

func Generate() ([]byte, error) {
	// make a device secret
	return crypto.RandomBytes(Size)
}

func keyringWorks() bool {
	if err := keyring.Set(keyringService, "probe", "probe"); err != nil {
		return false
	}
	keyring.Delete(keyringService, "probe")
	return true
}

func Pick(dir string) Provider {
	if keyringWorks() {
		return Keyring{}
	}

	return File{Path: filepath.Join(dir, "device.key")}
}

func For(backend uint8, dir string) (Provider, error) {
	switch backend {
	case BackendKeyring:
		return Keyring{}, nil
	case BackendFile:
		return File{Path: filepath.Join(dir, "device.key")}, nil
	}

	return nil, fmt.Errorf("%w: unknown backend %d", ErrUnavailable, backend)
}
