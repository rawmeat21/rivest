package store

import (
	"os"
	"path/filepath"
)

// replaces gievn path with data. If anything fails midway, the old
// file is restored
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)

	tmp, err := os.CreateTemp(dir, ".rivest-*.tmp")

	if err != nil {
		return err
	}

	tmpName := tmp.Name()

	done := false
	defer func() {

		if !done {
			tmp.Close()
			os.Remove(tmpName)
		}

	}()

	if _, err := tmp.Write(data); err != nil {
		return err
	}

	if err := tmp.Sync(); err != nil {
		return err
	}

	if err := tmp.Close(); err != nil {
		return err
	}

	if err := os.Rename(tmpName, path); err != nil {
		return err
	}

	done = true

	// flush directory entry
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}

	return nil
}