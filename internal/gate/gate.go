package gate

// a gate is simply a check

import (
	"fmt"
	"slices"
	"time"

	"github.com/rawmeat21/rivest/internal/crypto"
	"golang.org/x/crypto/argon2"
)

var DefaultParams = crypto.KDFParams{Time: 2, MemoryKiB: 32 * 1024, Threads: 2}

const deviceWindow = 15 * time.Second

type Config struct {
	Method    Method `json:"method"`
	Time      uint32 `json:"time,omitempty"`
	MemoryKiB uint32 `json:"memoryKiB,omitempty"`
	Threads   uint8  `json:"threads,omitempty"`
	Salt      []byte `json:"salt,omitempty"`
	Hash      []byte `json:"hash,omitempty"`
}

func (c Config) params() crypto.KDFParams {
	return crypto.KDFParams{
		Time: c.Time,
		MemoryKiB: c.MemoryKiB,
		Threads: c.Threads,
	}
}

func (c *Config) clone() *Config {
	cpy := *c
	cpy.Salt = slices.Clone(cpy.Salt)
	cpy.Hash = slices.Clone(cpy.Hash)

	return &cpy
}

func (c Config) validate() error {
	switch c.Method {
	case MethodNone, MethodDevice:
		if len(c.Salt) != 0 || len(c.Hash) != 0 {
			return fmt.Errorf("%w: %s has no secret to store", ErrBadConfig, c.Method)
		}
		return nil
	case MethodPIN, MethodPattern, MethodText:
		if len(c.Salt) != crypto.SaltSize || len(c.Hash) != crypto.KeySize {
			return fmt.Errorf("%w: wrong salt or hash length", ErrBadConfig)
		}
		if err := c.params().Validate(); err != nil {
			return fmt.Errorf("%w: %v", ErrBadConfig, err)
		}
		return nil
	}
 
	return fmt.Errorf("%w: %q", ErrBadMethod, string(c.Method))
}

func derive(p crypto.KDFParams, salt, encoded []byte) []byte {
	// pass in encoded [method]\x00[secret] to get a key
	
	return argon2.IDKey(encoded, salt, p.Time, p.MemoryKiB, p.Threads, crypto.KeySize) 
}


