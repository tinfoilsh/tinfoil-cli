package statefile

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStorageWriteProbeLeavesDirectoryUntouched(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "existing.json")
	const original = "existing metadata\n"
	require.NoError(t, os.WriteFile(path, []byte(original), fileMode))
	require.NoError(t, ProbeDirectory(dir))
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, original, string(data))
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1)
}

func TestPrivatePublicationAndLocking(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	path := filepath.Join(dir, "record.json")
	require.NoError(t, WriteJSON(path, map[string]string{"key": "first"}, true))
	require.ErrorIs(t, WriteJSON(path, map[string]string{"key": "second"}, true), os.ErrExist)
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "{\n  \"key\": \"first\"\n}\n", string(data))
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.EqualValues(t, fileMode, info.Mode().Perm())
	info, err = os.Stat(dir)
	require.NoError(t, err)
	require.EqualValues(t, dirMode, info.Mode().Perm())

	unlock, err := Lock(path)
	require.NoError(t, err)
	defer unlock()
	_, err = Lock(path)
	require.ErrorIs(t, err, ErrLocked)
	unlock()
	unlock, err = Lock(path)
	require.NoError(t, err)
	unlock()
	require.FileExists(t, path+".lock")

	require.NoError(t, WriteJSON(path, map[string]string{"key": "second"}, false))
	var record map[string]string
	require.NoError(t, ReadJSON(path, &record))
	require.Equal(t, "second", record["key"])
	require.NoError(t, Write(path, []byte("private invalid data"), false))
	err = ReadJSON(path, &record)
	require.ErrorContains(t, err, "invalid storage metadata")
	require.NotContains(t, err.Error(), "private invalid data")
}

func TestRejectsDirectoryAndLockSymlinks(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(t.TempDir(), "state")
	require.NoError(t, os.Symlink(dir, link))
	require.ErrorContains(t, PrepareDirectory(link), "symlink")
	path := filepath.Join(dir, "record.json")
	target := filepath.Join(dir, "target")
	require.NoError(t, os.WriteFile(target, []byte("retained"), fileMode))
	require.NoError(t, os.Symlink(target, path+".lock"))
	_, err := Lock(path)
	require.Error(t, err)
	data, err := os.ReadFile(target)
	require.NoError(t, err)
	require.Equal(t, "retained", string(data))
}
