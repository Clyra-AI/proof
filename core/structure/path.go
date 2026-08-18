package structure

import (
	"fmt"
	"path"
	"strings"
	"unicode"

	coreerr "github.com/Clyra-AI/proof/core/errors"
)

const (
	ErrorCodePathInvalid      = "structure.path_invalid"
	ErrorCodePathAmbiguous    = "structure.path_ambiguous"
	ErrorCodePathDuplicate    = "structure.path_duplicate"
	ErrorCodeUnlistedFile     = "structure.unlisted_file"
	ErrorCodeSymlinkAmbiguous = "structure.symlink_ambiguous"
)

type pathInfo struct {
	collisionKey string
	canonical    string
}

// ValidateListedPaths validates manifest paths and returns their normalized,
// slash-separated names. Strict verification requires callers to use the
// returned names for comparisons rather than platform-specific path cleaning.
func ValidateListedPaths(paths []string) (map[string]struct{}, error) {
	return validatePaths(paths, false)
}

// ValidateArchivePaths applies the same normalization rules to archive entry
// names and rejects aliases before callers read entry contents.
func ValidateArchivePaths(paths []string) (map[string]struct{}, error) {
	return validatePaths(paths, true)
}

// ValidatePath validates an observed file path and returns the portable key
// used for duplicate and membership checks.
func ValidatePath(raw string) (string, error) {
	info, err := normalizeRelativePath(raw, false)
	if err != nil {
		return "", err
	}
	if raw != info.canonical {
		return "", coreerr.New(
			coreerr.KindValidation,
			ErrorCodePathAmbiguous,
			fmt.Sprintf("artifact path is not canonical: %s", raw),
			coreerr.WithPath(raw),
		)
	}
	return info.collisionKey, nil
}

// ValidateArchivePath validates an observed archive entry path and returns the
// portable key used for duplicate and membership checks.
func ValidateArchivePath(raw string, isDir bool) (string, error) {
	info, err := normalizeRelativePath(raw, isDir)
	if err != nil {
		return "", err
	}
	if raw != info.canonical {
		return "", coreerr.New(
			coreerr.KindValidation,
			ErrorCodePathAmbiguous,
			fmt.Sprintf("artifact path is not canonical: %s", raw),
			coreerr.WithPath(raw),
		)
	}
	return info.collisionKey, nil
}

func validatePaths(paths []string, allowDirectories bool) (map[string]struct{}, error) {
	seen := make(map[string]struct{}, len(paths))
	for _, raw := range paths {
		info, err := normalizeRelativePath(raw, allowDirectories && hasDirectorySuffix(raw))
		if err != nil {
			return nil, err
		}
		if _, ok := seen[info.collisionKey]; ok {
			return nil, coreerr.New(
				coreerr.KindValidation,
				ErrorCodePathDuplicate,
				fmt.Sprintf("duplicate normalized artifact path: %s", info.collisionKey),
				coreerr.WithPath(raw),
			)
		}
		if raw != info.canonical {
			return nil, coreerr.New(
				coreerr.KindValidation,
				ErrorCodePathAmbiguous,
				fmt.Sprintf("artifact path is not canonical: %s", raw),
				coreerr.WithPath(raw),
			)
		}
		seen[info.collisionKey] = struct{}{}
	}
	return seen, nil
}

func UnlistedFileError(filePath string) error {
	return coreerr.New(
		coreerr.KindVerification,
		ErrorCodeUnlistedFile,
		fmt.Sprintf("artifact contains an unlisted file: %s", filePath),
		coreerr.WithPath(filePath),
	)
}

func SymlinkAmbiguityError(filePath string) error {
	return coreerr.New(
		coreerr.KindVerification,
		ErrorCodeSymlinkAmbiguous,
		fmt.Sprintf("artifact contains an ambiguous symbolic link: %s", filePath),
		coreerr.WithPath(filePath),
	)
}

func normalizeRelativePath(raw string, isDir bool) (pathInfo, error) {
	if raw == "" || strings.IndexByte(raw, 0) >= 0 {
		return pathInfo{}, coreerr.New(
			coreerr.KindValidation,
			ErrorCodePathInvalid,
			"artifact path must be a non-empty relative path",
			coreerr.WithPath(raw),
		)
	}

	slashPath := strings.ReplaceAll(raw, `\`, "/")
	if strings.HasPrefix(slashPath, "/") || hasWindowsVolumePrefix(slashPath) {
		return pathInfo{}, coreerr.New(
			coreerr.KindValidation,
			ErrorCodePathInvalid,
			fmt.Sprintf("artifact path must be relative: %s", raw),
			coreerr.WithPath(raw),
		)
	}

	trimmed := slashPath
	if isDir {
		trimmed = strings.TrimSuffix(trimmed, "/")
	}
	normalized := path.Clean(trimmed)
	if normalized == "." || normalized == ".." || strings.HasPrefix(normalized, "../") {
		return pathInfo{}, coreerr.New(
			coreerr.KindValidation,
			ErrorCodePathInvalid,
			fmt.Sprintf("artifact path escapes its root: %s", raw),
			coreerr.WithPath(raw),
		)
	}
	collisionKey, err := portableCollisionKey(normalized, raw)
	if err != nil {
		return pathInfo{}, err
	}
	canonical := collisionKey
	if isDir {
		canonical += "/"
	}
	return pathInfo{collisionKey: collisionKey, canonical: canonical}, nil
}

func portableCollisionKey(normalized string, raw string) (string, error) {
	parts := strings.Split(normalized, "/")
	canonicalParts := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimRight(part, " .")
		if trimmed == "" {
			return "", coreerr.New(
				coreerr.KindValidation,
				ErrorCodePathAmbiguous,
				fmt.Sprintf("artifact path is not canonical: %s", raw),
				coreerr.WithPath(raw),
			)
		}
		canonicalParts = append(canonicalParts, strings.ToLower(trimmed))
	}
	return strings.Join(canonicalParts, "/"), nil
}

func hasDirectorySuffix(raw string) bool {
	return strings.HasSuffix(strings.ReplaceAll(raw, `\`, "/"), "/")
}

func hasWindowsVolumePrefix(value string) bool {
	return len(value) >= 2 && value[1] == ':' && unicode.IsLetter(rune(value[0]))
}
