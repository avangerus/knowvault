package workspaceapi

import (
	"context"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/address"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/evidence"
)

// Exact reads retain the same current workspace authority as ordinary reads,
// but bind to the immutable version explicitly named by a canonical address.
// Keeping these capabilities separate leaves fragment-ID reads current-only.
type EvidenceExactVersion interface {
	ReadExactVersion(context.Context, database.AccessContext, string, string, string) (evidence.Fragment, error)
}

type EvidenceWholeObjectExactVersion interface {
	ReadObjectExactVersion(context.Context, database.AccessContext, string, string, string) (evidence.WholeObject, error)
}

func exactAddressVersion(selector *address.Address, refVersionID string) string {
	if selector == nil {
		return ""
	}
	if refVersionID != "" {
		return refVersionID
	}
	return selector.Version
}

func (handler *Handler) readEvidenceSelection(ctx context.Context, access database.AccessContext, workspaceID, fragmentID string, selector *address.Address, refVersionID string) (evidence.Fragment, error) {
	if selector != nil {
		if exact, ok := handler.evidence.(EvidenceExactVersion); ok {
			return exact.ReadExactVersion(ctx, access, workspaceID, fragmentID, exactAddressVersion(selector, refVersionID))
		}
	}
	// A legacy fragment-only composition cannot expose historical bytes. Its
	// current read still undergoes the caller's full address/hash verification.
	return handler.evidence.Read(ctx, access, workspaceID, fragmentID)
}

func (handler *Handler) readEvidenceObjectSelection(ctx context.Context, access database.AccessContext, workspaceID, fragmentID string, selector *address.Address, refVersionID string) (evidence.WholeObject, error) {
	if selector != nil {
		if exact, ok := handler.evidence.(EvidenceWholeObjectExactVersion); ok {
			return exact.ReadObjectExactVersion(ctx, access, workspaceID, fragmentID, exactAddressVersion(selector, refVersionID))
		}
	}
	current, ok := handler.evidenceWholeObjectCapability()
	if !ok {
		return evidence.WholeObject{}, evidence.ErrNotFound
	}
	return current.ReadObject(ctx, access, workspaceID, fragmentID)
}

// EnableEvidencePageOrigin accepts only the trusted deployment origin. The
// request Host, Origin and forwarding headers never control emitted links.
func (handler *Handler) EnableEvidencePageOrigin(origin string) error {
	parsed, err := url.Parse(origin)
	if handler == nil || err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		parsed.Opaque != "" || parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" ||
		parsed.ForceQuery || parsed.Fragment != "" || parsed.String() != origin || strings.TrimSpace(origin) != origin {
		return errors.New("workspaceapi: invalid evidence page origin")
	}
	handler.evidencePageOrigin = origin
	return nil
}

func (handler *Handler) evidenceSourcePageURL(workspaceID, fragmentID, canonicalAddress string) string {
	if handler == nil || handler.evidencePageOrigin == "" || workspaceID == "" || fragmentID == "" || canonicalAddress == "" {
		return ""
	}
	return handler.evidencePageOrigin + "/#evidence/" + url.PathEscape(workspaceID) + "/" + url.PathEscape(fragmentID) +
		"?address=" + url.QueryEscape(canonicalAddress)
}

func mcpSourcePageText(pageURL string) string {
	if pageURL == "" {
		return ""
	}
	return " source_page_url=" + strconv.Quote(pageURL)
}

func (handler *Handler) evidenceFragmentPageURL(workspaceID string, fragment evidence.Fragment) string {
	canonical, err := handler.canonicalEvidenceAddress(fragment)
	if err != nil {
		return ""
	}
	return handler.evidenceSourcePageURL(workspaceID, fragment.FragmentID, canonical.String())
}

// A human citation page accepts the same verified ref and whole-text addresses
// as knowvault_read, but discloses only the addressed fragment projection.
func (handler *Handler) readEvidencePageSelection(ctx context.Context, access database.AccessContext, workspaceID, fragmentID string, selector *address.Address) (evidence.Fragment, error) {
	refVersionID := ""
	if selector != nil {
		resolution := handler.mcpReadAddressResolution(ctx, access, workspaceID, *selector)
		if resolution.Available && resolution.ObjectSeen && !resolution.VersionKnown {
			return evidence.Fragment{}, evidence.ErrNotFound
		}
		refVersionID = resolution.RefVersionID
	}
	fragment, err := handler.readEvidenceSelection(ctx, access, workspaceID, fragmentID, selector, refVersionID)
	if err != nil || selector == nil {
		return fragment, err
	}
	identityMatches := func(value evidence.Fragment) bool {
		return selector.Source == value.SourceObjectID && selector.Object == value.FragmentID &&
			mcpReadAddressVersionMatches(*selector, value.SourceVersionID, refVersionID)
	}
	if !identityMatches(fragment) {
		return evidence.Fragment{}, evidence.ErrNotFound
	}
	if handler.verifyAddressSpan(fragment.Text, *selector) {
		return fragment, nil
	}
	if selector.SpanKind != address.SpanKindText || selector.CharEnd <= utf8.RuneCount(fragment.Text) {
		return evidence.Fragment{}, evidence.ErrNotFound
	}
	object, err := handler.readEvidenceObjectSelection(ctx, access, workspaceID, fragmentID, selector, refVersionID)
	if err != nil || !identityMatches(object.Fragment) || !handler.verifyAddressSpan(object.Text, *selector) {
		return evidence.Fragment{}, evidence.ErrNotFound
	}
	return object.Fragment, nil
}
