package quick

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/rawmeat21/rivest/internal/crypto"
	"github.com/rawmeat21/rivest/internal/fsutil"
)

const (
	fileLen   = 107
	prefixLen = 34 // the part before WrappedDEK

	DefaultMaxTries = 5

	ModeDeviceOnly   uint8 = 0 // device secret only (the OS already checked the user)
	ModeUnlockSecret uint8 = 1 // PIN, pattern or text, plus the device secret
)

var magic = [6]byte{'R', 'I', 'V', 'Q', 'K', '1'}

// 107 bytes
type file struct {
	Magic      [6]byte                     // 6
	Backend    uint8                       // 1
	Mode       uint8                       // 1
	MaxTries   uint8                       // 1
	Time       uint32                      // 4
	MemoryKiB  uint32                      // 4
	Threads    uint8                       // 1
	Salt       [crypto.SaltSize]byte       // 16
	WrappedDEK [crypto.WrappedDEKSize]byte // 72
	Tries      uint8                       // 1
}

func (f *file) params() crypto.KDFParams {
	return crypto.KDFParams{
		Time:      f.Time,
		MemoryKiB: f.MemoryKiB,
		Threads:   f.Threads,
	}
}

func (f *file) marshal() []byte {

	// convert file struct -> 107B binary
	var buf bytes.Buffer

	if err := binary.Write(&buf, binary.BigEndian, f); err != nil {
		panic(err)
	}

	return buf.Bytes()
}

func read(path string) (*file, error) {
	data, err := os.ReadFile(path)

	if err != nil {
		return nil, err
	}

	if len(data) != fileLen {
		return nil, ErrBadFile
	}

	var f file

	if err := binary.Read(bytes.NewReader(data), binary.BigEndian, &f); err != nil {
		return nil, ErrBadFile
	}

	if f.Magic != magic || f.MaxTries == 0 {
		return nil, ErrBadFile
	}

	if err := f.params().Validate(); err != nil {
		return nil, err
	}

	return &f, nil
}

func Create(path string, dek, unlock, deviceSecret []byte, backend, maxTries uint8) error {

	if maxTries == 0 {
		maxTries = DefaultMaxTries
	}

	salt, err := crypto.NewSalt()

	if err != nil {
		return err
	}

	params := crypto.DefaultKDFParams

	f := file{
		Magic:     magic,
		Backend:   backend,
		MaxTries:  maxTries,
		Time:      params.Time,
		MemoryKiB: params.MemoryKiB,
		Threads:   params.Threads,
	}

	if len(unlock) > 0 {
		f.Mode = ModeUnlockSecret
	}

	copy(f.Salt[:], salt)

	key, err := crypto.DeriveQuickKey(unlock, deviceSecret, salt, params)

	if err != nil {
		return err
	}

	defer crypto.Wipe(key)

	wrapped, err := crypto.WrapDEK(key, dek, f.marshal()[:prefixLen])
	if err != nil {
		return err
	}

	copy(f.WrappedDEK[:], wrapped)

	return fsutil.WriteFileAtomic(path, f.marshal())
}

func Info(path string) (backend uint8, needsSecret bool, err error) {
	f, err := read(path)
	if err != nil {
		return 0, false, err
	}
	return f.Backend, f.Mode == ModeUnlockSecret, nil
}

// Unlock returns the DEK (the caller must wipe it)
func Unlock(path string, unlock, deviceSecret []byte) ([]byte, error) {
	f, err := read(path)
	if err != nil {
		return nil, err
	}

	if f.Tries >= f.MaxTries {
		os.Remove(path)
		return nil, ErrTooManyTries
	}

	if f.Mode == ModeUnlockSecret && len(unlock) == 0 {
		return nil, ErrNeedSecret // not a real guess, so it doesn't count
	}

	if len(deviceSecret) != crypto.KeySize {
		return nil, fmt.Errorf("%w: bad device secret", crypto.ErrBadInput)
	}

	// Count the attempt BEFORE checking
	f.Tries++
	if err := fsutil.WriteFileAtomic(path, f.marshal()); err != nil {
		return nil, err
	}

	key, err := crypto.DeriveQuickKey(unlock, deviceSecret, f.Salt[:], f.params())
	if err != nil {
		return nil, err
	}
	defer crypto.Wipe(key)

	dek, err := crypto.UnwrapDEK(key, f.WrappedDEK[:], f.marshal()[:prefixLen])

	if err != nil {
		if f.Tries >= f.MaxTries {
			os.Remove(path)
			return nil, ErrTooManyTries
		}
		return nil, ErrWrongSecret
	}

	f.Tries = 0 // success: reset the counter

	if err := fsutil.WriteFileAtomic(path, f.marshal()); err != nil {
		crypto.Wipe(dek)
		return nil, err
	}

	return dek, nil
}

// disable quick unlock
func Remove(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}
