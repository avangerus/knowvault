package modelgateway

// Profiles are immutable, administrator-mounted adapter choices. Workspace
// authorization remains with the caller; this package only applies the mounted
// external-runtime allow-list and never accepts transport settings from users.
import (
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"
)

const maximumGenerationProfiles = 8

type ProfileInfo struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	Location  string `json:"location"`
	IsDefault bool   `json:"is_default"`
}

// ProfileConfig is an operator/test construction seam, not a request payload.
// NewProfileRegistry takes ownership by constructing private adapter copies.
type ProfileConfig struct {
	ID     string
	Label  string
	Config LabAdapterConfig
}

type generationProfile struct {
	info    ProfileInfo
	adapter *LabAdapter
}

type ProfileRegistry struct {
	defaultID string
	profiles  []generationProfile
}

func NewProfileRegistry(defaultID string, configs []ProfileConfig) (*ProfileRegistry, error) {
	if !validProfileID(defaultID) || len(configs) == 0 || len(configs) > maximumGenerationProfiles {
		return nil, &Error{code: CodeProfile}
	}
	registry := &ProfileRegistry{defaultID: defaultID}
	seen := make(map[string]bool, len(configs))
	for _, config := range configs {
		if !validProfileID(config.ID) || !validProfileLabel(config.Label) || seen[config.ID] {
			_ = registry.Close()
			return nil, &Error{code: CodeProfile}
		}
		seen[config.ID] = true
		adapter, err := NewLabAdapter(config.Config)
		if err != nil {
			_ = registry.Close()
			return nil, err
		}
		location := "INTERNAL"
		if adapter.RuntimeScope() == RuntimeScopeExternalWorkspaceScoped {
			location = "EXTERNAL"
		}
		registry.profiles = append(registry.profiles, generationProfile{
			info:    ProfileInfo{ID: config.ID, Label: config.Label, Location: location, IsDefault: config.ID == defaultID},
			adapter: adapter,
		})
	}
	if registry.Default() == nil || (len(configs) > 1 && registry.Default().RuntimeScope() != RuntimeScopeLocalLab) {
		_ = registry.Close()
		return nil, &Error{code: CodeProfile}
	}
	return registry, nil
}

// List returns content-free copies only for profiles allowed in this workspace.
// The caller must authorize current workspace access before exposing the list.
func (registry *ProfileRegistry) List(workspaceID string) []ProfileInfo {
	result := make([]ProfileInfo, 0)
	if registry != nil {
		for _, profile := range registry.profiles {
			if profile.adapter.AllowsWorkspace(workspaceID) {
				result = append(result, profile.info)
			}
		}
	}
	return result
}

// Select never changes shared state. Empty selects the configured default;
// an explicit unknown or forbidden choice fails without falling back.
func (registry *ProfileRegistry) Select(workspaceID, id string) (*LabAdapter, error) {
	if registry != nil {
		if id == "" {
			id = registry.defaultID
		}
		for _, profile := range registry.profiles {
			if profile.info.ID == id && profile.adapter.AllowsWorkspace(workspaceID) {
				return profile.adapter, nil
			}
		}
	}
	return nil, &Error{code: CodeProfile}
}

// Default is the unchanged adapter for legacy composition paths. It grants no
// workspace access; those paths retain their existing authorization checks.
func (registry *ProfileRegistry) Default() *LabAdapter {
	if registry != nil {
		for _, profile := range registry.profiles {
			if profile.info.IsDefault {
				return profile.adapter
			}
		}
	}
	return nil
}

func (registry *ProfileRegistry) Close() error {
	var errs []error
	if registry != nil {
		for _, profile := range registry.profiles {
			errs = append(errs, profile.adapter.Close())
		}
	}
	return errors.Join(errs...)
}

// ValidProfileID is shared by mounted profiles and the request-field boundary.
// Empty is handled separately by callers as the omitted/default selection.
func ValidProfileID(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for index, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			continue
		}
		if index == 0 || (r != '-' && r != '_' && r != '.') {
			return false
		}
	}
	return true
}

func validProfileID(value string) bool { return ValidProfileID(value) }

func validProfileLabel(value string) bool {
	if value == "" || !utf8.ValidString(value) || utf8.RuneCountInString(value) > 80 || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if !unicode.IsPrint(r) || r == '<' || r == '>' {
			return false
		}
	}
	return true
}
