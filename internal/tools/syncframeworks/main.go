package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

func main() {
	root, err := repoRoot()
	if err != nil {
		fail(err)
	}
	srcDir := filepath.Join(root, "core", "framework")
	dstDir := filepath.Join(root, "frameworks")
	if err := syncFrameworks(srcDir, dstDir); err != nil {
		fail(err)
	}
}

func repoRoot() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("locate source file")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..")), nil
}

func syncFrameworks(srcDir, dstDir string) error {
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return err
	}

	sourceFiles := make(map[string]struct{})
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".yaml" {
			continue
		}
		sourceFiles[entry.Name()] = struct{}{}
		names = append(names, entry.Name())
	}
	sort.Strings(names)

	for _, name := range names {
		srcPath := filepath.Join(srcDir, name)
		dstPath := filepath.Join(dstDir, name)
		if err := copyFile(srcPath, dstPath); err != nil {
			return err
		}
	}

	dstEntries, err := os.ReadDir(dstDir)
	if err != nil {
		return err
	}
	for _, entry := range dstEntries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".yaml" {
			continue
		}
		if _, ok := sourceFiles[entry.Name()]; ok {
			continue
		}
		if err := os.Remove(filepath.Join(dstDir, entry.Name())); err != nil {
			return err
		}
	}
	return nil
}

func copyFile(srcPath, dstPath string) error {
	src, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer func() {
		_ = src.Close()
	}()

	dst, err := os.Create(dstPath)
	if err != nil {
		return err
	}
	if _, err := io.Copy(dst, src); err != nil {
		_ = dst.Close()
		return err
	}
	if err := dst.Close(); err != nil {
		return err
	}
	return os.Chmod(dstPath, 0o644)
}

func fail(err error) {
	_, _ = fmt.Fprintf(os.Stderr, "sync frameworks: %s\n", strings.TrimSpace(err.Error()))
	os.Exit(1)
}
