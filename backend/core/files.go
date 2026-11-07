package core

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var (
	readRoots  = []string{"/etc/letsencrypt", "/etc/wireguard", "/etc/godeb-play"}
	writeRoots = []string{"/etc/wireguard", "/etc/godeb-play"}
)

// ReadAdminFile reads a root-owned file under /etc/letsencrypt, /etc/wireguard
// or /etc/godeb-play. Paths outside those trees are rejected. Permission errors
// retry through sudo -n.
func ReadAdminFile(path string) ([]byte, error) {
	clean := filepath.Clean(path)
	if !underRoot(clean, readRoots) {
		return nil, fmt.Errorf("Pfad nicht erlaubt: %s", clean)
	}
	data, err := os.ReadFile(clean)
	if err == nil || os.Geteuid() == 0 || !os.IsPermission(err) {
		return data, err
	}
	res := Run(context.Background(), "sudo", "-n", "--", "cat", clean)
	if res.Err != nil {
		return nil, sudoError(res, err)
	}
	return []byte(res.Stdout), nil
}

// sudoError maps a "No such file" from the sudo fallback back to fs.ErrNotExist.
func sudoError(res CommandResult, fallback error) error {
	if strings.Contains(res.Stderr, "No such file or directory") {
		return fs.ErrNotExist
	}
	return fallback
}

// ListAdminDir returns the sorted names of regular files in an allowed directory.
func ListAdminDir(dir string) ([]string, error) {
	clean := filepath.Clean(dir)
	if !underRoot(clean, readRoots) {
		return nil, fmt.Errorf("Pfad nicht erlaubt: %s", clean)
	}
	entries, err := os.ReadDir(clean)
	if err == nil {
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			if entry.Type().IsRegular() {
				names = append(names, entry.Name())
			}
		}
		return names, nil
	}
	if os.Geteuid() == 0 || !os.IsPermission(err) {
		return nil, err
	}
	res := Run(context.Background(), "sudo", "-n", "--", "find", clean, "-mindepth", "1", "-maxdepth", "1", "-type", "f", "-printf", "%f\n")
	if res.Err != nil {
		return nil, sudoError(res, err)
	}
	names := []string{}
	for _, line := range strings.Split(res.Stdout, "\n") {
		if line != "" {
			names = append(names, line)
		}
	}
	sort.Strings(names)
	return names, nil
}

// WriteAdminFile replaces a file under /etc/wireguard or /etc/godeb-play. Missing
// parent directories are created with mode 0700. As root the write is atomic;
// otherwise it goes through sudo -n install.
func WriteAdminFile(path string, data []byte, perm os.FileMode) error {
	clean := filepath.Clean(path)
	if !underRoot(clean, writeRoots) || isRoot(clean, writeRoots) {
		return fmt.Errorf("Pfad nicht erlaubt: %s", clean)
	}
	dir := filepath.Dir(clean)
	if os.Geteuid() != 0 {
		ctx := context.Background()
		if res := Run(ctx, "sudo", "-n", "--", "install", "-d", "-m", "0700", dir); res.Err != nil {
			return fmt.Errorf("%s anlegen: %s", dir, res.Detail())
		}
		mode := fmt.Sprintf("%04o", perm.Perm())
		if res := RunInput(ctx, string(data), "sudo", "-n", "--", "install", "-m", mode, "/dev/stdin", clean); res.Err != nil {
			return fmt.Errorf("%s schreiben: %s", clean, res.Detail())
		}
		return nil
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(clean)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), clean)
}

// RemoveAdminFile deletes a file under /etc/wireguard or /etc/godeb-play (not the
// directory itself). Used e.g. to drop a WireGuard client file after download.
func RemoveAdminFile(path string) error {
	clean := filepath.Clean(path)
	if !underRoot(clean, writeRoots) || isRoot(clean, writeRoots) {
		return fmt.Errorf("Pfad nicht erlaubt: %s", clean)
	}
	if os.Geteuid() != 0 {
		res := Run(context.Background(), "sudo", "-n", "--", "rm", "-f", "--", clean)
		if res.Err != nil {
			return fmt.Errorf("%s löschen: %s", clean, res.Detail())
		}
		return nil
	}
	err := os.Remove(clean)
	if os.IsNotExist(err) {
		return fs.ErrNotExist
	}
	return err
}

func underRoot(path string, roots []string) bool {
	for _, root := range roots {
		if path == root || strings.HasPrefix(path, root+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}

func isRoot(path string, roots []string) bool {
	for _, root := range roots {
		if path == root {
			return true
		}
	}
	return false
}
