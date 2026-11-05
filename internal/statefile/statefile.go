package statefile

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

const (
	dirMode  = 0o700
	fileMode = 0o600
)

var ErrLocked = errors.New("locked by another running tinfoil command")

func ReadJSON(path string, out any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("invalid storage metadata; restore it from a trusted backup")
	}
	return nil
}

func PrepareDirectory(dir string) error {
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("storage directory must not be a symlink")
	}
	return os.Chmod(dir, dirMode)
}

func WriteJSON(path string, value any, exclusive bool) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding storage metadata: %w", err)
	}
	if err := PrepareDirectory(filepath.Dir(path)); err != nil {
		return fmt.Errorf("preparing storage directory: %w", err)
	}
	return Write(path, append(data, '\n'), exclusive)
}

func ProbeDirectory(dir string) error {
	f, err := os.CreateTemp(dir, ".storage-probe-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := f.Close(); err != nil {
		return err
	}
	path := f.Name() + ".json"
	defer os.Remove(path)
	if err := Write(path, []byte("{}\n"), true); err != nil {
		return err
	}
	if err := Write(path, []byte("{}\n"), false); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	return os.Remove(f.Name())
}

// The temporary file is synced before publication; exclusive publication
// prevents concurrent commands from replacing an existing custody record.
func Write(path string, data []byte, exclusive bool) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".storage-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if exclusive {
		err = os.Link(f.Name(), path)
	} else {
		err = os.Rename(f.Name(), path)
	}
	if err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func Lock(path string) (func(), error) {
	if err := PrepareDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_WRONLY|syscall.O_NOFOLLOW, fileMode)
	if err != nil {
		return nil, err
	}
	// The kernel releases the lock when the process exits; removing the file would race a waiting locker.
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("%s is %w", path, ErrLocked)
		}
		return nil, err
	}
	return func() { _ = f.Close() }, nil
}
