package devsecret

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/rawmeat21/rivest/internal/fsutil"
	"github.com/zalando/go-keyring"
)

const (
	keyringService = "rivest"
	keyringUser    = "device-secret"
)

func decode(text string) ([]byte, error) {
	secret, err := hex.DecodeString(strings.TrimSpace(text))
	if err != nil || len(secret) != Size {
		return nil, fmt.Errorf("%w: stored value is damaged", ErrNotFound)
	}

	return secret, nil
}

// the OS keyring provider object

type Keyring struct{}

func (Keyring) Backend() uint8 {
	return BackendKeyring
}

func (Keyring) Load() ([]byte, error) {
	text, err := keyring.Get(keyringService, keyringUser)

	if errors.Is(err, keyring.ErrNotFound) {
		return nil, ErrNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}

	return decode(text)
}

func (Keyring) Save(secret []byte) error {
	if err := keyring.Set(keyringService, keyringUser, hex.EncodeToString(secret)); err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}

	return nil
}

func (Keyring) Delete() error {
	if err := keyring.Delete(keyringService, keyringUser); err != nil && !errors.Is(err, keyring.ErrNotFound) {
		return err
	}

	return nil
}

type File struct {
	Path string
}

func (File) Backend() uint8 {
	return BackendFile
}

func (f File) Load() ([]byte, error) {
	data, err := os.ReadFile(f.Path)

	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotFound
	}

	if err != nil {
		return nil, err
	}

	return decode(string(data))
}

func (f File) Save(secret []byte) error {
	if err := os.MkdirAll(filepath.Dir(f.Path), 0o700); err != nil {
		return err
	}

	return fsutil.WriteFileAtomic(f.Path, []byte(hex.EncodeToString(secret)+"\n"))
}

func (f File) Delete() error {
	if err := os.Remove(f.Path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}

	return nil
}
