// Package metriccomparemount loads one operator-approved comparison metric
// from a fixed, optional server mount.
package metriccomparemount

import (
	jsontext "encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"io"
	"os"
	"path/filepath"

	"knowvault.local/verified-workspace/internal/metriccompare"
)

const (
	DefaultMountRoot    = "/run/knowvault/analytics"
	profileFilename     = "metric-compare-profile.json"
	maximumProfileBytes = 256 << 10
)

type ErrorCode string

const (
	CodeMountUnavailable ErrorCode = "METRIC_COMPARE_MOUNT_UNAVAILABLE"
	CodeMountInvalid     ErrorCode = "METRIC_COMPARE_MOUNT_INVALID"
)

// Error carries no path, file content, or decoder detail.
type Error struct{ code ErrorCode }

func (e *Error) Error() string { return string(e.code) }

func CodeOf(err error) ErrorCode {
	if err == nil {
		return ""
	}
	var mountErr *Error
	if errors.As(err, &mountErr) {
		return mountErr.code
	}
	return CodeMountInvalid
}

// Mount binds exactly one sealed metric to one workspace and connection.
type Mount struct {
	WorkspaceID  string
	ConnectionID string
	Profile      metriccompare.Profile
}

type wire struct {
	WorkspaceID  string       `json:"workspace_id"`
	ConnectionID string       `json:"connection_id"`
	Profile      *profileWire `json:"profile"`
}

type profileWire struct {
	ExposedSchemaRevision int64        `json:"exposed_schema_revision"`
	MetricID              string       `json:"metric_id"`
	Description           string       `json:"description"`
	Unit                  string       `json:"unit"`
	Schema                string       `json:"schema"`
	View                  string       `json:"view"`
	SubjectColumn         string       `json:"subject_column"`
	SnapshotColumn        string       `json:"snapshot_column"`
	MeasureColumn         string       `json:"measure_column"`
	Timezone              string       `json:"timezone"`
	Filters               []filterWire `json:"filters"`
}

type filterWire struct {
	Column string `json:"column"`
	Value  string `json:"value"`
}

func validID(value string) bool {
	if len(value) == 0 || len(value) > 200 {
		return false
	}
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}

func LoadMounted() (Mount, error) { return LoadMountedAt(DefaultMountRoot) }

// LoadMountedAt is the explicit-root seam for deployment verification and tests.
func LoadMountedAt(root string) (Mount, error) {
	rootInfo, err := os.Lstat(root)
	if err != nil {
		if os.IsNotExist(err) {
			return Mount{}, &Error{CodeMountUnavailable}
		}
		return Mount{}, &Error{CodeMountInvalid}
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return Mount{}, &Error{CodeMountInvalid}
	}
	path := filepath.Join(root, profileFilename)
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Mount{}, &Error{CodeMountUnavailable}
		}
		return Mount{}, &Error{CodeMountInvalid}
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > maximumProfileBytes {
		return Mount{}, &Error{CodeMountInvalid}
	}
	file, err := os.Open(path)
	if err != nil {
		return Mount{}, &Error{CodeMountInvalid}
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() {
		return Mount{}, &Error{CodeMountInvalid}
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximumProfileBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maximumProfileBytes {
		return Mount{}, &Error{CodeMountInvalid}
	}
	var decoded wire
	if err := jsonv2.Unmarshal(raw, &decoded, jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)); err != nil ||
		!validID(decoded.WorkspaceID) || !validID(decoded.ConnectionID) || decoded.Profile == nil {
		return Mount{}, &Error{CodeMountInvalid}
	}
	p := decoded.Profile
	filters := make([]metriccompare.FixedFilter, len(p.Filters))
	for i, f := range p.Filters {
		filters[i] = metriccompare.FixedFilter{Column: f.Column, Value: f.Value}
	}
	profile, err := metriccompare.NewProfile(metriccompare.ProfileSpec{
		ExposedSchemaRevision: p.ExposedSchemaRevision, MetricID: p.MetricID,
		Description: p.Description, Unit: p.Unit,
		Schema: p.Schema, View: p.View, SubjectColumn: p.SubjectColumn,
		SnapshotColumn: p.SnapshotColumn, MeasureColumn: p.MeasureColumn,
		Timezone: p.Timezone, Filters: filters,
	})
	if err != nil {
		return Mount{}, &Error{CodeMountInvalid}
	}
	return Mount{WorkspaceID: decoded.WorkspaceID, ConnectionID: decoded.ConnectionID, Profile: profile}, nil
}
