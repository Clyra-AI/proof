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

var (
	repoRootFunc                 = repoRoot
	syncFrameworksFunc           = syncFrameworks
	runFunc                      = run
	exitFunc                     = os.Exit
	stderrWriter       io.Writer = os.Stderr
)

func main() {
	if err := runFunc(); err != nil {
		fail(err)
	}
}

func run() error {
	root, err := repoRootFunc()
	if err != nil {
		return err
	}
	srcDir := filepath.Join(root, "core", "framework")
	dstDir := filepath.Join(root, "frameworks")
	return syncFrameworksFunc(srcDir, dstDir)
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
	if err := os.MkdirAll(dstDir, 0o750); err != nil {
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
		if err := copyFile(srcDir, dstDir, name); err != nil {
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

func copyFile(srcDir, dstDir, name string) error {
	srcRoot, err := os.OpenRoot(srcDir)
	if err != nil {
		return err
	}
	defer func() {
		_ = srcRoot.Close()
	}()

	dstRoot, err := os.OpenRoot(dstDir)
	if err != nil {
		return err
	}
	defer func() {
		_ = dstRoot.Close()
	}()

	src, err := srcRoot.Open(name)
	if err != nil {
		return err
	}
	defer func() {
		_ = src.Close()
	}()

	dst, err := dstRoot.OpenFile(name, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(dst, src); err != nil {
		_ = dst.Close()
		return err
	}
	return dst.Close()
}

func fail(err error) {
	_, _ = fmt.Fprintf(stderrWriter, "sync frameworks: %s\n", strings.TrimSpace(err.Error()))
	exitFunc(1)
}
