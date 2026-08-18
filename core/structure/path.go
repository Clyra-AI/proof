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

// ValidateListedPaths validates manifest paths and returns their normalized,
// slash-separated names. Strict verification requires callers to use the
// returned names for comparisons rather than platform-specific path cleaning.
func ValidateListedPaths(paths []string) (map[string]struct{}, error) {
	seen := make(map[string]struct{}, len(paths))
	for _, raw := range paths {
		normalized, canonical, err := normalizeRelativePath(raw)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[normalized]; ok {
			return nil, coreerr.New(
				coreerr.KindValidation,
				ErrorCodePathDuplicate,
				fmt.Sprintf("duplicate normalized artifact path: %s", normalized),
				coreerr.WithPath(raw),
			)
		}
		if !canonical {
			return nil, coreerr.New(
				coreerr.KindValidation,
				ErrorCodePathAmbiguous,
				fmt.Sprintf("artifact path is not canonical: %s", raw),
				coreerr.WithPath(raw),
			)
		}
		seen[normalized] = struct{}{}
	}
	return seen, nil
}

// ValidateArchivePaths applies the same normalization rules to archive entry
// names and rejects aliases before callers read entry contents.
func ValidateArchivePaths(paths []string) (map[string]struct{}, error) {
	return ValidateListedPaths(paths)
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

func normalizeRelativePath(raw string) (normalized string, canonical bool, err error) {
	if raw == "" || strings.IndexByte(raw, 0) >= 0 {
		return "", false, coreerr.New(
			coreerr.KindValidation,
			ErrorCodePathInvalid,
			"artifact path must be a non-empty relative path",
			coreerr.WithPath(raw),
		)
	}

	slashPath := strings.ReplaceAll(raw, `\`, "/")
	if strings.HasPrefix(slashPath, "/") || hasWindowsVolumePrefix(slashPath) {
		return "", false, coreerr.New(
			coreerr.KindValidation,
			ErrorCodePathInvalid,
			fmt.Sprintf("artifact path must be relative: %s", raw),
			coreerr.WithPath(raw),
		)
	}

	normalized = path.Clean(slashPath)
	if normalized == "." || normalized == ".." || strings.HasPrefix(normalized, "../") {
		return "", false, coreerr.New(
			coreerr.KindValidation,
			ErrorCodePathInvalid,
			fmt.Sprintf("artifact path escapes its root: %s", raw),
			coreerr.WithPath(raw),
		)
	}
	return normalized, raw == normalized, nil
}

func hasWindowsVolumePrefix(value string) bool {
	return len(value) >= 2 && value[1] == ':' && unicode.IsLetter(rune(value[0]))
}
