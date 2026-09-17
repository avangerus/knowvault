package modelgateway

import (
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

const (
	ProfilesSchemaVersion = "model-gateway-profiles-v1"
	profilesFilename      = "profiles.json"
)

type mountedProfiles struct {
	SchemaVersion    string                   `json:"schema_version"`
	DefaultProfileID string                   `json:"default_profile_id"`
	Profiles         []mountedProfileLocation `json:"profiles"`
}

type mountedProfileLocation struct {
	ID              string `json:"id"`
	Label           string `json:"label"`
	ConfigDirectory string `json:"config_directory"`
}

func LoadMountedProfiles() (*ProfileRegistry, error) {
	return LoadMountedProfilesAt(DefaultLabMountRoot)
}

// LoadMountedProfilesAt preserves the single config.json mount when the
// optional manifest is absent. A present malformed manifest/profile fails
// startup; it never silently disables a profile or restores the legacy path.
func LoadMountedProfilesAt(rootPath string) (*ProfileRegistry, error) {
	if rootPath == "" {
		return nil, &Error{code: CodeLabMountUnavailable}
	}
	manifestPath := filepath.Join(rootPath, profilesFilename)
	info, err := os.Lstat(manifestPath)
	if os.IsNotExist(err) {
		config, err := LoadLabMountedConfigAt(rootPath)
		if err != nil {
			return nil, err
		}
		label := config.ModelID
		if !validProfileLabel(label) {
			label = "Default model"
		}
		return NewProfileRegistry("default", []ProfileConfig{{ID: "default", Label: label, Config: config}})
	}
	if err != nil || !info.Mode().IsRegular() || !profileMountDirectory(rootPath) {
		return nil, &Error{code: CodeLabMountInvalid}
	}
	raw, err := os.ReadFile(manifestPath)
	if err != nil || len(raw) == 0 || len(raw) > maximumLabConfigBytes {
		return nil, &Error{code: CodeLabMountInvalid}
	}
	var mounted mountedProfiles
	if err := jsonv2.Unmarshal(raw, &mounted, jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)); err != nil {
		return nil, &Error{code: CodeLabMountInvalid, cause: err}
	}
	if mounted.SchemaVersion != ProfilesSchemaVersion || !validProfileID(mounted.DefaultProfileID) || len(mounted.Profiles) == 0 || len(mounted.Profiles) > maximumGenerationProfiles {
		return nil, &Error{code: CodeLabMountInvalid}
	}
	configs := make([]ProfileConfig, 0, len(mounted.Profiles))
	seenIDs := make(map[string]bool, len(mounted.Profiles))
	seenDirectories := make(map[string]bool, len(mounted.Profiles))
	defaultFound := false
	for _, profile := range mounted.Profiles {
		isDefault := profile.ID == mounted.DefaultProfileID
		if !validProfileID(profile.ID) || !validProfileLabel(profile.Label) || seenIDs[profile.ID] || seenDirectories[profile.ConfigDirectory] ||
			(isDefault && profile.ConfigDirectory != ".") || (!isDefault && !validProfileID(profile.ConfigDirectory)) {
			return nil, &Error{code: CodeLabMountInvalid}
		}
		seenIDs[profile.ID] = true
		seenDirectories[profile.ConfigDirectory] = true
		directory := filepath.Join(rootPath, profile.ConfigDirectory)
		if !profileMountDirectory(directory) {
			return nil, &Error{code: CodeLabMountInvalid}
		}
		configPath := filepath.Join(directory, labConfigFilename)
		if !regularProfileMountFile(configPath) {
			return nil, &Error{code: CodeLabMountInvalid}
		}
		rawConfig, err := os.ReadFile(configPath)
		if err != nil || len(rawConfig) == 0 || len(rawConfig) > maximumLabConfigBytes {
			return nil, &Error{code: CodeLabMountInvalid}
		}
		config, err := parseLabMountedConfig(directory, rawConfig, true)
		if err != nil {
			return nil, err
		}
		if !profileRuntimeLocationConsistent(config) || (isDefault && config.RuntimeScope() != RuntimeScopeLocalLab) {
			return nil, &Error{code: CodeLabMountInvalid}
		}
		defaultFound = defaultFound || isDefault
		configs = append(configs, ProfileConfig{ID: profile.ID, Label: profile.Label, Config: config})
	}
	if !defaultFound {
		return nil, &Error{code: CodeLabMountInvalid}
	}
	registry, err := NewProfileRegistry(mounted.DefaultProfileID, configs)
	if err != nil {
		return nil, &Error{code: CodeLabMountInvalid, cause: err}
	}
	return registry, nil
}

func profileMountDirectory(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0
}

func regularProfileMountFile(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular()
}

func validProfileMountFilename(value string) bool {
	return value != "" && value != "." && value != ".." && filepath.Base(value) == value && !strings.ContainsAny(value, `/\`)
}

// Legacy mounts retain their existing endpoint policy. Named profiles must
// classify the endpoint truthfully: a scoped cloud profile is public HTTPS;
// a local profile continues to require a private literal address.
func profileRuntimeLocationConsistent(config LabAdapterConfig) bool {
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil {
		return false
	}
	ip := net.ParseIP(endpoint.Hostname())
	private := ip != nil && (ip.IsPrivate() || ip.IsLoopback())
	if config.RuntimeScope() == RuntimeScopeExternalWorkspaceScoped {
		return (ip == nil || (ip.IsGlobalUnicast() && !private)) && endpoint.Scheme == "https"
	}
	return private
}
