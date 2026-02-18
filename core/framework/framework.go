package framework

import (
	"embed"
	"fmt"
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
	name := idOrFile
	if !strings.HasSuffix(name, ".yaml") {
		name = name + ".yaml"
	}
	raw, err := frameworkFS.ReadFile(name)
	if err != nil {
		return nil, fmt.Errorf("load framework %s: %w", idOrFile, err)
	}
	var f Framework
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return nil, err
	}
	if f.Framework.ID == "" {
		return nil, fmt.Errorf("framework %s missing id", idOrFile)
	}
	return &f, nil
}

func countControls(in []Control) int {
	total := 0
	for _, c := range in {
		total++
		total += countControls(c.Children)
	}
	return total
}
