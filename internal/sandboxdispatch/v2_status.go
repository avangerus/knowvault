package sandboxdispatch

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path"
	"regexp"
	"time"
)

const (
	SupervisorStatusSchemaVersionV1 = "sandbox-dispatcher-status-v1"
	v2StatusMaximumBytes            = 4096
	v2StatusHeartbeatInterval       = time.Second
	v2StatusValidityWindow          = 5 * time.Second

	v2StatusRunning  = "running"
	v2StatusRed      = "red"
	v2StatusStopping = "stopping"

	v2RoleEmpty     = "empty"
	v2RoleHandedOff = "handed_off"
	v2RoleReady     = "ready"
	v2RoleBusy      = "busy"
	v2RoleReaped    = "reaped"
	v2RoleRed       = "red"
)

var (
	ErrSupervisorStatusUnavailable = errors.New("sandboxdispatch: supervisor status unavailable")
	ErrSupervisorStatusUnsupported = errors.New("sandboxdispatch: supervisor status unsupported")
	v2StatusEpochPattern           = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

type v2StatusWriter interface {
	Write([]byte) error
	Close() error
}

type v2StatusRoleState struct {
	State         string
	HandoffID     string
	LeaseDeadline time.Time
}

type v2StatusRoleDocument struct {
	State         string  `json:"state"`
	HandoffID     *string `json:"handoff_id"`
	LeaseDeadline *string `json:"lease_deadline,omitempty"`
}

type v2DispatcherStatusDocument struct {
	SchemaVersion   string                          `json:"schema_version"`
	DispatcherEpoch string                          `json:"dispatcher_epoch"`
	Sequence        uint64                          `json:"sequence"`
	WrittenAt       string                          `json:"written_at"`
	ValidUntil      string                          `json:"valid_until"`
	DispatcherState string                          `json:"dispatcher_state"`
	Roles           map[string]v2StatusRoleDocument `json:"roles"`
}

func validV2SupervisorStatusPath(statusPath, handoffSocketPath string) bool {
	if statusPath == "" {
		return true
	}
	if path.IsAbs(statusPath) == false || path.Clean(statusPath) != statusPath ||
		path.Base(statusPath) != "status.json" || !path.IsAbs(handoffSocketPath) || path.Clean(handoffSocketPath) != handoffSocketPath {
		return false
	}
	return statusPath == path.Join(path.Dir(handoffSocketPath), "status.json")
}

func newV2StatusEpoch() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", ErrSupervisorStatusUnavailable
	}
	return hex.EncodeToString(value[:]), nil
}

func initialV2StatusRoles(cfg V2Config) map[string]v2StatusRoleState {
	roles := map[string]v2StatusRoleState{
		ParserTypeOffice: {State: v2RoleEmpty},
		ParserTypePDF:    {State: v2RoleEmpty},
	}
	if cfg.ocrPath() != "" {
		roles[ParserTypeOCR] = v2StatusRoleState{State: v2RoleEmpty}
	}
	return roles
}

func (d *DispatcherV2) nextV2StatusLocked(now time.Time) v2DispatcherStatusDocument {
	d.statusSequence++
	state := v2StatusRunning
	if d.red {
		state = v2StatusRed
	} else if d.closed {
		state = v2StatusStopping
	}
	roles := make(map[string]v2StatusRoleDocument, len(d.statusRoles))
	for role, status := range d.statusRoles {
		if d.red {
			status.State = v2RoleRed
			status.LeaseDeadline = time.Time{}
		}
		var handoffID *string
		if status.HandoffID != "" {
			id := status.HandoffID
			handoffID = &id
		}
		var deadline *string
		if status.State == v2RoleBusy && !status.LeaseDeadline.IsZero() {
			value := status.LeaseDeadline.UTC().Format(time.RFC3339Nano)
			deadline = &value
		}
		roles[role] = v2StatusRoleDocument{State: status.State, HandoffID: handoffID, LeaseDeadline: deadline}
	}
	now = now.UTC()
	return v2DispatcherStatusDocument{
		SchemaVersion:   SupervisorStatusSchemaVersionV1,
		DispatcherEpoch: d.statusEpoch,
		Sequence:        d.statusSequence,
		WrittenAt:       now.Format(time.RFC3339Nano),
		ValidUntil:      now.Add(v2StatusValidityWindow).Format(time.RFC3339Nano),
		DispatcherState: state,
		Roles:           roles,
	}
}

func validateV2StatusDocument(status v2DispatcherStatusDocument) bool {
	if status.SchemaVersion != SupervisorStatusSchemaVersionV1 || !v2StatusEpochPattern.MatchString(status.DispatcherEpoch) ||
		status.Sequence == 0 || (status.DispatcherState != v2StatusRunning && status.DispatcherState != v2StatusRed && status.DispatcherState != v2StatusStopping) {
		return false
	}
	writtenAt, err := time.Parse(time.RFC3339Nano, status.WrittenAt)
	if err != nil {
		return false
	}
	validUntil, err := time.Parse(time.RFC3339Nano, status.ValidUntil)
	if err != nil || !validUntil.After(writtenAt) || validUntil.Sub(writtenAt) != v2StatusValidityWindow {
		return false
	}
	if _, office := status.Roles[ParserTypeOffice]; !office {
		return false
	}
	if _, pdf := status.Roles[ParserTypePDF]; !pdf {
		return false
	}
	if len(status.Roles) != 2 && len(status.Roles) != 3 {
		return false
	}
	for role, value := range status.Roles {
		if role != ParserTypeOffice && role != ParserTypePDF && role != ParserTypeOCR {
			return false
		}
		if value.State != v2RoleEmpty && value.State != v2RoleHandedOff && value.State != v2RoleReady &&
			value.State != v2RoleBusy && value.State != v2RoleReaped && value.State != v2RoleRed {
			return false
		}
		if value.HandoffID != nil && !supervisorHandoffIDRe.MatchString(*value.HandoffID) {
			return false
		}
		switch value.State {
		case v2RoleEmpty:
			if value.HandoffID != nil || value.LeaseDeadline != nil {
				return false
			}
		case v2RoleHandedOff, v2RoleReady, v2RoleReaped:
			if value.HandoffID == nil || value.LeaseDeadline != nil {
				return false
			}
		case v2RoleBusy:
			if value.HandoffID == nil || value.LeaseDeadline == nil {
				return false
			}
		case v2RoleRed:
			if value.LeaseDeadline != nil || status.DispatcherState != v2StatusRed {
				return false
			}
		}
		if value.LeaseDeadline != nil {
			if value.State != v2RoleBusy {
				return false
			}
			if _, err := time.Parse(time.RFC3339Nano, *value.LeaseDeadline); err != nil {
				return false
			}
		}
	}
	if status.DispatcherState == v2StatusRed {
		for _, role := range status.Roles {
			if role.State != v2RoleRed {
				return false
			}
		}
	}
	return true
}

func marshalV2StatusDocument(status v2DispatcherStatusDocument) ([]byte, error) {
	if !validateV2StatusDocument(status) {
		return nil, ErrSupervisorStatusUnavailable
	}
	encoded, err := json.Marshal(status)
	if err != nil || len(encoded) == 0 || len(encoded) > v2StatusMaximumBytes {
		return nil, ErrSupervisorStatusUnavailable
	}
	return encoded, nil
}

func (d *DispatcherV2) initializeV2Status() error {
	if d.cfg.SupervisorStatusPath == "" {
		return nil
	}
	writer, err := newV2StatusWriter(d.cfg.SupervisorStatusPath)
	if err != nil {
		return err
	}
	epoch, err := newV2StatusEpoch()
	if err != nil {
		_ = writer.Close()
		return ErrSupervisorStatusUnavailable
	}
	d.statusWriter = writer
	d.statusEpoch = epoch
	d.statusRoles = initialV2StatusRoles(d.cfg)
	d.mu.Lock()
	status := d.nextV2StatusLocked(time.Now())
	d.mu.Unlock()
	encoded, err := marshalV2StatusDocument(status)
	if err == nil {
		err = writer.Write(encoded)
	}
	if err != nil {
		_ = writer.Close()
		d.statusWriter = nil
		return ErrSupervisorStatusUnavailable
	}
	d.startV2StatusHeartbeat()
	return nil
}

func (d *DispatcherV2) startV2StatusHeartbeat() {
	if d == nil || d.statusWriter == nil {
		return
	}
	d.statusLifeMu.Lock()
	if d.statusStarted || d.statusStopped {
		d.statusLifeMu.Unlock()
		return
	}
	d.statusStop = make(chan struct{})
	d.statusDone = make(chan struct{})
	d.statusStarted = true
	stop, done := d.statusStop, d.statusDone
	d.statusLifeMu.Unlock()
	go func() {
		defer close(done)
		ticker := time.NewTicker(v2StatusHeartbeatInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				d.publishV2Status()
			case <-stop:
				return
			}
		}
	}()
}

func (d *DispatcherV2) stopV2StatusHeartbeat() {
	if d == nil {
		return
	}
	d.statusLifeMu.Lock()
	if d.statusStarted && !d.statusStopped {
		close(d.statusStop)
		d.statusStopped = true
	}
	done := d.statusDone
	d.statusLifeMu.Unlock()
	if done != nil {
		<-done
	}
	d.statusCloseOnce.Do(func() {
		d.statusWriteMu.Lock()
		if d.statusWriter != nil {
			_ = d.statusWriter.Close()
		}
		d.statusWriteMu.Unlock()
	})
}

func (d *DispatcherV2) publishV2Status() bool {
	if d == nil || d.statusWriter == nil {
		return true
	}
	d.mu.Lock()
	status := d.nextV2StatusLocked(time.Now())
	d.mu.Unlock()
	if err := d.writeV2StatusDocument(status); err == nil {
		return true
	}
	d.latchV2Red()
	d.writeV2StatusBestEffort()
	return false
}

func (d *DispatcherV2) writeV2StatusBestEffort() {
	if d == nil || d.statusWriter == nil {
		return
	}
	d.mu.Lock()
	status := d.nextV2StatusLocked(time.Now())
	d.mu.Unlock()
	_ = d.writeV2StatusDocument(status)
}

func (d *DispatcherV2) writeV2StatusDocument(status v2DispatcherStatusDocument) error {
	encoded, err := marshalV2StatusDocument(status)
	if err != nil {
		return err
	}
	d.statusWriteMu.Lock()
	defer d.statusWriteMu.Unlock()
	d.mu.Lock()
	defer d.mu.Unlock()
	stale := status.Sequence != d.statusSequence
	if stale {
		return nil
	}
	if d.statusWriter == nil {
		return ErrSupervisorStatusUnavailable
	}
	if err := d.statusWriter.Write(encoded); err != nil {
		// Keep admission serialized with the durable write so no handler can
		// pass its d.mu red check after failure is observed but before RED.
		d.red = true
		for role, current := range d.statusRoles {
			current.State = v2RoleRed
			current.LeaseDeadline = time.Time{}
			d.statusRoles[role] = current
		}
		return err
	}
	return nil
}

func (d *DispatcherV2) setV2RoleStatusLocked(role, handoffID, state string, leaseDeadline time.Time) bool {
	current, ok := d.statusRoles[role]
	if !ok || current.HandoffID != handoffID || (d.red && state != v2RoleRed) {
		return false
	}
	switch state {
	case v2RoleReady:
		if current.State != v2RoleHandedOff {
			return false
		}
	case v2RoleBusy:
		if current.State != v2RoleReady || leaseDeadline.IsZero() {
			return false
		}
	case v2RoleReaped:
		if current.State != v2RoleHandedOff && current.State != v2RoleReady && current.State != v2RoleBusy {
			return false
		}
	case v2RoleRed:
	case v2RoleEmpty, v2RoleHandedOff:
		return false
	default:
		return false
	}
	if state != v2RoleBusy {
		leaseDeadline = time.Time{}
	}
	if current.State == state && current.LeaseDeadline.Equal(leaseDeadline) {
		return false
	}
	current.State = state
	current.LeaseDeadline = leaseDeadline
	d.statusRoles[role] = current
	return true
}

func (d *DispatcherV2) setV2RoleStatus(role, handoffID, state string, leaseDeadline time.Time) bool {
	d.mu.Lock()
	changed := d.setV2RoleStatusLocked(role, handoffID, state, leaseDeadline)
	d.mu.Unlock()
	if changed {
		return d.publishV2Status()
	}
	return true
}

func (d *DispatcherV2) setV2HandoffStatusLocked(role, handoffID string) bool {
	if !d.canSetV2HandoffStatusLocked(role, handoffID) {
		return false
	}
	d.statusRoles[role] = v2StatusRoleState{State: v2RoleHandedOff, HandoffID: handoffID}
	return true
}

func (d *DispatcherV2) canSetV2HandoffStatusLocked(role, handoffID string) bool {
	current, ok := d.statusRoles[role]
	if !ok || d.red || handoffID == "" || current.HandoffID == handoffID ||
		(current.State != v2RoleEmpty && current.State != v2RoleReaped) {
		return false
	}
	return true
}
