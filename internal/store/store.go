package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/rawmeat21/rivest/internal/crypto"
	"github.com/rawmeat21/rivest/internal/fsutil"
	"github.com/rawmeat21/rivest/internal/model"
)

// a vault is a file which stores information about all accounts of the user
type Vault struct {
	path   string // where is the vault file
	header Header // header (see header.go for information about what a header contains)
	dek    []byte // 32 byte key, use to derive other keys
	DB     *model.AccountDatabase // the database which holds our accounts
}

// what gets encrypted into the file body
type contents struct {
	Accounts []*model.Account `json:"accounts"` // all our accounts
}

// create a new vault file
func Create(path string, password, secretKey []byte) (*Vault, error) {

	if _, err := os.Stat(path); err == nil {
		return nil, ErrExists
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}

	salt, err := crypto.NewSalt()
	if err != nil {
		return nil, err
	}

	dek, err := crypto.NewDEK()
	if err != nil {
		return nil, err
	}

	params := crypto.DefaultKDFParams
	h := newHeader(params, salt)

	kek, err := crypto.DeriveKEK(password, secretKey, salt, params)

	if err != nil {
		crypto.Wipe(dek)
		return nil, err
	}

	defer crypto.Wipe(kek)

	wrapped, err := crypto.WrapDEK(kek, dek, h.marshal()[:prefixLen])

	if err != nil {
		crypto.Wipe(dek)
		return nil, err
	}

	copy(h.WrappedDEK[:], wrapped)

	v := &Vault{path: path, header: h, dek: dek, DB: model.NewAccountDatabase()}

	if err := v.Save(); err != nil {
		v.Close()
		return nil, err
	}

	return v, nil
}

func load(path string, data []byte, h *Header, dek []byte) (*Vault, error) {
	plain, err := crypto.OpenBody(dek, data[headerLen:], data[:headerLen])

	if err != nil {
		crypto.Wipe(dek)
		return nil, err
	}
	defer crypto.Wipe(plain)

	var c contents
	if err := json.Unmarshal(plain, &c); err != nil {
		crypto.Wipe(dek)
		return nil, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}

	db := model.NewAccountDatabase()
	for _, a := range c.Accounts {
		if err := db.Add(a); err != nil {
			crypto.Wipe(dek)
			return nil, fmt.Errorf("%w: %v", ErrCorrupt, err)
		}
	}

	return &Vault{path: path, header: *h, dek: dek, DB: db}, nil
}



// unlocks a vault file
func Open(path string, password, secretKey []byte) (*Vault, error) {

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	h, err := parseHeader(data)
	if err != nil {
		return nil, err
	}

	kek, err := crypto.DeriveKEK(password, secretKey, h.Salt[:], h.params())
	if err != nil {
		return nil, err
	}
	defer crypto.Wipe(kek)

	// a wrong password or Secret Key fails here
	dek, err := crypto.UnwrapDEK(kek, h.WrappedDEK[:], data[:prefixLen])
	if err != nil {
		return nil, err
	}

	return load(path, data, h, slices.Clone(dek))
}

func OpenWithDEK(path string, dek []byte) (*Vault, error) {
	// used to open the vault with just the DEK

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	h, err := parseHeader(data)
	if err != nil {
		return nil, err
	}

	return load(path, data, h, dek)
}

func (v *Vault) ExportDEK() ([]byte) {
	return slices.Clone(v.dek)
}

// Save writes the current accounts to disk.
func (v *Vault) Save() error {
	plain, err := json.Marshal(contents{Accounts: v.DB.All()})
	if err != nil {
		return err
	}
	defer crypto.Wipe(plain)

	h := v.header // a copy: only keep the new counter if the write works
	h.Counter++
	hdr := h.marshal()

	sealed, err := crypto.SealBody(v.dek, plain, hdr)
	if err != nil {
		return err
	}

	file := append(hdr, sealed...) // header first, then the encrypted body
	if err := fsutil.WriteFileAtomic(v.path, file); err != nil {
		return err
	}
	v.header = h
	return nil
}

// wipes the DEK. The vault is locked afterwards
func (v *Vault) Close() {
	crypto.Wipe(v.dek)
	v.dek = nil
}


func (v *Vault) SealField(accountID, fieldName string, plaintext []byte) ([]byte, error) {
	return crypto.SealField(v.dek, accountID, fieldName, plaintext)
}

func (v *Vault) OpenField(accountID, fieldName string, sealed []byte) ([]byte, error) {
	return crypto.OpenField(v.dek, accountID, fieldName, sealed)
}