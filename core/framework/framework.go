package framework

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed *.yaml
var frameworkFS embed.FS

type Framework struct {
	Framework struct {
		ID      string `yaml:"id" json:"id"`
		Version string `yaml:"version" json:"version"`
		Title   string `yaml:"title" json:"title"`
	} `yaml:"framework" json:"framework"`
	Controls []Control `yaml:"controls" json:"controls"`
}

type Control struct {
	ID                  string    `yaml:"id" json:"id"`
	Title               string    `yaml:"title" json:"title"`
	RequiredRecordTypes []string  `yaml:"required_record_types,omitempty" json:"required_record_types,omitempty"`
	MinimumFrequency    string    `yaml:"minimum_frequency,omitempty" json:"minimum_frequency,omitempty"`
	RequiredFields      []string  `yaml:"required_fields,omitempty" json:"required_fields,omitempty"`
	Children            []Control `yaml:"children,omitempty" json:"children,omitempty"`
}

type Info struct {
	ID           string `json:"id"`
	Version      string `json:"version"`
	Title        string `json:"title"`
	ControlCount int    `json:"control_count"`
	File         string `json:"file"`
}

func List() ([]Info, error) {
	entries, err := frameworkFS.ReadDir(".")
	if err != nil {
		return nil, err
	}
	out := make([]Info, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		f, err := Load(filepath.Base(e.Name()))
		if err != nil {
			return nil, err
		}
		out = append(out, Info{
			ID:           f.Framework.ID,
			Version:      f.Framework.Version,
			Title:        f.Framework.Title,
			ControlCount: countControls(f.Controls),
			File:         e.Name(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func Load(idOrFile string) (*Framework, error) {
	if isLikelyPath(idOrFile) {
		info, err := os.Stat(idOrFile)
		if err != nil {
			return nil, fmt.Errorf("load framework file %s: %w", idOrFile, err)
		}
		if info.IsDir() {
			return nil, fmt.Errorf("load framework file %s: path is a directory", idOrFile)
		}
		return LoadFile(idOrFile)
	}

	embedded, embeddedErr := loadEmbedded(idOrFile)
	if embeddedErr == nil {
		return embedded, nil
	}

	info, err := os.Stat(idOrFile)
	if err == nil {
		if info.IsDir() {
			return nil, fmt.Errorf("load framework file %s: path is a directory", idOrFile)
		}
		return LoadFile(idOrFile)
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("load framework file %s: %w", idOrFile, err)
	}
	return nil, embeddedErr
}

func loadEmbedded(idOrFile string) (*Framework, error) {
	name := idOrFile
	if !strings.HasSuffix(name, ".yaml") {
		name += ".yaml"
	}
	raw, err := frameworkFS.ReadFile(name)
	if err != nil {
		return nil, fmt.Errorf("load framework %s: %w", idOrFile, err)
	}
	return parseFramework(idOrFile, raw)
}

func LoadFile(path string) (*Framework, error) {
	// #nosec G304 -- path is intentionally caller-provided for runtime custom framework loading.
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("load framework file %s: %w", path, err)
	}
	return parseFramework(path, raw)
}

func isLikelyPath(value string) bool {
	if value == "" {
		return false
	}
	if filepath.IsAbs(value) {
		return true
	}
	if strings.HasPrefix(value, ".") {
		return true
	}
	return strings.ContainsAny(value, `/\`)
}

func parseFramework(idOrFile string, raw []byte) (*Framework, error) {
	var f Framework
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return nil, err
	}
	if f.Framework.ID == "" {
		return nil, fmt.Errorf("framework %s missing id", idOrFile)
	}
	if len(f.Controls) == 0 {
		return nil, fmt.Errorf("framework %s has no controls", idOrFile)
	}
	if err := validateControls(f.Controls, "controls"); err != nil {
		return nil, fmt.Errorf("framework %s invalid: %w", idOrFile, err)
	}
	return &f, nil
}

func validateControls(controls []Control, path string) error {
	for i, c := range controls {
		controlPath := fmt.Sprintf("%s[%d]", path, i)
		if strings.TrimSpace(c.ID) == "" {
			return fmt.Errorf("%s missing id", controlPath)
		}
		if strings.TrimSpace(c.Title) == "" {
			return fmt.Errorf("%s (%s) missing title", controlPath, c.ID)
		}
		if len(c.RequiredRecordTypes) == 0 {
			return fmt.Errorf("%s (%s) missing required_record_types", controlPath, c.ID)
		}
		if strings.TrimSpace(c.MinimumFrequency) == "" {
			return fmt.Errorf("%s (%s) missing minimum_frequency", controlPath, c.ID)
		}
		if len(c.RequiredFields) == 0 {
			return fmt.Errorf("%s (%s) missing required_fields", controlPath, c.ID)
		}
		for _, t := range c.RequiredRecordTypes {
			if strings.TrimSpace(t) == "" {
				return fmt.Errorf("%s (%s) has blank required_record_types entry", controlPath, c.ID)
			}
		}
		for _, field := range c.RequiredFields {
			if strings.TrimSpace(field) == "" {
				return fmt.Errorf("%s (%s) has blank required_fields entry", controlPath, c.ID)
			}
		}
		if err := validateControls(c.Children, controlPath+".children"); err != nil {
			return err
		}
	}
	return nil
}

func countControls(in []Control) int {
	total := 0
	for _, c := range in {
		total++
		total += countControls(c.Children)
	}
	return total
}
