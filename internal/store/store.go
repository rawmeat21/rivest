package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/rawmeat21/rivest/internal/crypto"
	"github.com/rawmeat21/rivest/internal/model"
)

// Vault is an open (unlocked) vault, it holds the DEK in memory.
type Vault struct {
	path   string
	header Header
	dek    []byte
	DB     *model.AccountDatabase
}

// what gets encrypted into the file body
type contents struct {
	Accounts []*model.Account `json:"accounts"`
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

	// lock the DEK
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
	if err := writeFileAtomic(v.path, file); err != nil {
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