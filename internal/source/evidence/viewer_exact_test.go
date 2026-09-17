package evidence

import (
	"context"
	"errors"
	"testing"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/platform/database"
)

func exactTestFragment(fragmentID, versionID string) Fragment {
	fragment := authorizedReadFragment()
	fragment.FragmentID = fragmentID
	fragment.SourceVersionID = versionID
	return fragment
}

func TestReadExactVersionForwardsVersionAndAuditsSuccess(t *testing.T) {
	const (
		workspaceID = "ws_exact_0001"
		fragmentID  = "frag_exact_0001"
		versionID   = "src_ver_0001"
	)
	sink := &recordingSink{}
	viewer := &Viewer{
		audit: sink,
		authorizeExactFn: func(_ context.Context, _ database.AccessContext, gotWorkspace, gotFragment, gotVersion string) (bool, error) {
			if gotWorkspace != workspaceID || gotFragment != fragmentID || gotVersion != versionID {
				t.Fatalf("authorization got workspace/fragment/version %q/%q/%q", gotWorkspace, gotFragment, gotVersion)
			}
			return true, nil
		},
		readExactFn: func(_ context.Context, _ database.AccessContext, gotWorkspace, gotFragment, gotVersion string) (Fragment, error) {
			if gotWorkspace != workspaceID || gotFragment != fragmentID || gotVersion != versionID {
				t.Fatalf("read got workspace/fragment/version %q/%q/%q", gotWorkspace, gotFragment, gotVersion)
			}
			if len(sink.appended) != 1 || sink.appended[0].Action != audit.ActionEvidenceReadAdmitted {
				t.Fatal("exact fragment was read before durable admission")
			}
			return exactTestFragment(fragmentID, versionID), nil
		},
	}

	fragment, err := viewer.ReadExactVersion(context.Background(), evidenceAccess(database.ActorKindHuman), workspaceID, fragmentID, versionID)
	if err != nil {
		t.Fatalf("ReadExactVersion = %v, want nil", err)
	}
	if fragment.FragmentID != fragmentID || fragment.SourceVersionID != versionID {
		t.Fatalf("exact fragment = %#v", fragment)
	}
	if len(sink.appended) != 2 || sink.appended[0].Action != audit.ActionEvidenceReadAdmitted || sink.appended[1].Action != audit.ActionCitationOpened {
		t.Fatalf("events = %#v, want admission then citation.opened", sink.appended)
	}
	if sink.appended[1].ResourceID != versionID {
		t.Fatalf("opened resource_id = %q, want exact version %q", sink.appended[1].ResourceID, versionID)
	}
}

func TestReadExactVersionDenialDoesNotReadOrAdmit(t *testing.T) {
	sink := &recordingSink{}
	readRan := false
	viewer := &Viewer{
		audit: sink,
		authorizeExactFn: func(_ context.Context, _ database.AccessContext, _, _, gotVersion string) (bool, error) {
			if gotVersion != "src_ver_old_0001" {
				t.Fatalf("authorization version = %q", gotVersion)
			}
			return false, nil
		},
		readExactFn: func(context.Context, database.AccessContext, string, string, string) (Fragment, error) {
			readRan = true
			return exactTestFragment("frag_exact_0001", "src_ver_old_0001"), nil
		},
	}

	fragment, err := viewer.ReadExactVersion(context.Background(), evidenceAccess(database.ActorKindHuman), "ws_exact_0001", "frag_exact_0001", "src_ver_old_0001")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("denied exact read = %v, want ErrNotFound", err)
	}
	if readRan || len(sink.appended) != 0 || fragment.FragmentID != "" || fragment.Text != nil {
		t.Fatalf("denied exact read ran or leaked: read=%v events=%d fragment=%#v", readRan, len(sink.appended), fragment)
	}
}

func TestReadExactVersionAdmissionFailureDoesNotFetch(t *testing.T) {
	readRan := false
	viewer := &Viewer{
		audit: failingSink{},
		authorizeExactFn: func(context.Context, database.AccessContext, string, string, string) (bool, error) {
			return true, nil
		},
		readExactFn: func(context.Context, database.AccessContext, string, string, string) (Fragment, error) {
			readRan = true
			return exactTestFragment("frag_exact_0001", "src_ver_old_0001"), nil
		},
	}

	fragment, err := viewer.ReadExactVersion(context.Background(), evidenceAccess(database.ActorKindHuman), "ws_exact_0001", "frag_exact_0001", "src_ver_old_0001")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("failed exact admission = %v, want ErrNotFound", err)
	}
	if readRan || fragment.FragmentID != "" || fragment.Text != nil {
		t.Fatalf("exact fragment fetched or leaked after failed admission: read=%v fragment=%#v", readRan, fragment)
	}
}

func TestReadExactVersionFailureAfterAdmissionLeavesNoPartialResult(t *testing.T) {
	sink := &recordingSink{}
	viewer := &Viewer{
		audit: sink,
		authorizeExactFn: func(context.Context, database.AccessContext, string, string, string) (bool, error) {
			return true, nil
		},
		readExactFn: func(_ context.Context, _ database.AccessContext, _, _, gotVersion string) (Fragment, error) {
			if gotVersion != "src_ver_old_0001" {
				t.Fatalf("read version = %q", gotVersion)
			}
			return Fragment{Text: []byte("secret")}, errors.New("injected read failure")
		},
	}

	fragment, err := viewer.ReadExactVersion(context.Background(), evidenceAccess(database.ActorKindHuman), "ws_exact_0001", "frag_exact_0001", "src_ver_old_0001")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("post-admission exact failure = %v, want ErrNotFound", err)
	}
	if fragment.FragmentID != "" || fragment.Text != nil {
		t.Fatalf("partial exact result leaked: %#v", fragment)
	}
	if len(sink.appended) != 2 || sink.appended[0].Action != audit.ActionEvidenceReadAdmitted || sink.appended[1].Action != audit.ActionEvidenceReadFailed {
		t.Fatalf("events = %#v, want admission then failure", sink.appended)
	}
}

func TestReadExactVersionRejectsMismatchedReturnedVersion(t *testing.T) {
	sink := &recordingSink{}
	viewer := &Viewer{
		audit: sink,
		authorizeExactFn: func(context.Context, database.AccessContext, string, string, string) (bool, error) {
			return true, nil
		},
		readExactFn: func(context.Context, database.AccessContext, string, string, string) (Fragment, error) {
			return exactTestFragment("frag_exact_0001", "src_ver_other_0001"), nil
		},
	}
	fragment, err := viewer.ReadExactVersion(context.Background(), evidenceAccess(database.ActorKindHuman), "ws_exact_0001", "frag_exact_0001", "src_ver_old_0001")
	if !errors.Is(err, ErrNotFound) || fragment.FragmentID != "" || fragment.Text != nil {
		t.Fatalf("mismatched source version result = %#v, %v; want content-free ErrNotFound", fragment, err)
	}
	if len(sink.appended) != 2 || sink.appended[1].Action != audit.ActionEvidenceReadFailed {
		t.Fatalf("mismatch events = %#v, want admission then failure", sink.appended)
	}
}

func TestReadObjectExactVersionForwardsVersionAndAuditsSuccess(t *testing.T) {
	const (
		workspaceID = "ws_exact_0001"
		fragmentID  = "frag_exact_0001"
		versionID   = "src_ver_old_0001"
	)
	sink := &recordingSink{}
	viewer := &Viewer{
		audit: sink,
		authorizeExactFn: func(_ context.Context, _ database.AccessContext, gotWorkspace, gotFragment, gotVersion string) (bool, error) {
			if gotWorkspace != workspaceID || gotFragment != fragmentID || gotVersion != versionID {
				t.Fatalf("authorization got workspace/fragment/version %q/%q/%q", gotWorkspace, gotFragment, gotVersion)
			}
			return true, nil
		},
		readObjectExactFn: func(_ context.Context, _ database.AccessContext, gotWorkspace, gotFragment, gotVersion string) (WholeObject, error) {
			if gotWorkspace != workspaceID || gotFragment != fragmentID || gotVersion != versionID {
				t.Fatalf("assembly got workspace/fragment/version %q/%q/%q", gotWorkspace, gotFragment, gotVersion)
			}
			if len(sink.appended) != 1 || sink.appended[0].Action != audit.ActionEvidenceReadAdmitted {
				t.Fatal("exact object was assembled before durable admission")
			}
			return WholeObject{Fragment: exactTestFragment(fragmentID, versionID), Text: []byte("historical canonical text"), FragmentCount: 1}, nil
		},
	}

	object, err := viewer.ReadObjectExactVersion(context.Background(), evidenceAccess(database.ActorKindHuman), workspaceID, fragmentID, versionID)
	if err != nil {
		t.Fatalf("ReadObjectExactVersion = %v, want nil", err)
	}
	if string(object.Text) != "historical canonical text" || object.Fragment.SourceVersionID != versionID {
		t.Fatalf("exact whole object = %#v", object)
	}
	if len(sink.appended) != 2 || sink.appended[0].Action != audit.ActionEvidenceReadAdmitted || sink.appended[1].Action != audit.ActionCitationOpened {
		t.Fatalf("events = %#v, want admission then citation.opened", sink.appended)
	}
	if sink.appended[1].ResourceID != versionID {
		t.Fatalf("opened resource_id = %q, want exact version %q", sink.appended[1].ResourceID, versionID)
	}
}

func TestReadObjectExactVersionDenialIsContentFree(t *testing.T) {
	sink := &recordingSink{}
	assemblyRan := false
	viewer := &Viewer{
		audit: sink,
		authorizeExactFn: func(context.Context, database.AccessContext, string, string, string) (bool, error) {
			return false, nil
		},
		readObjectExactFn: func(context.Context, database.AccessContext, string, string, string) (WholeObject, error) {
			assemblyRan = true
			return WholeObject{Text: []byte("secret")}, nil
		},
	}

	object, err := viewer.ReadObjectExactVersion(context.Background(), evidenceAccess(database.ActorKindHuman), "ws_exact_0001", "frag_exact_0001", "src_ver_old_0001")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("denied exact object = %v, want ErrNotFound", err)
	}
	if assemblyRan || object.Text != nil || object.Fragment.FragmentID != "" {
		t.Fatalf("denial ran assembly or leaked text: assembly=%v object=%#v", assemblyRan, object)
	}
	if len(sink.appended) != 1 {
		t.Fatalf("denial events = %#v, want one content-free denial", sink.appended)
	}
	denial := sink.appended[0]
	if denial.Outcome != audit.OutcomeDenied || denial.ErrorCode == nil || *denial.ErrorCode != auditObjectDeniedCode || denial.WorkspaceID != nil {
		t.Fatalf("denial event = %#v, want classed denial without workspace or content", denial)
	}
}

func TestReadObjectExactVersionFailureAfterAdmissionLeavesNoPartialResult(t *testing.T) {
	sink := &recordingSink{}
	viewer := &Viewer{
		audit: sink,
		authorizeExactFn: func(context.Context, database.AccessContext, string, string, string) (bool, error) {
			return true, nil
		},
		readObjectExactFn: func(context.Context, database.AccessContext, string, string, string) (WholeObject, error) {
			return WholeObject{Text: []byte("secret")}, errors.New("injected whole-object failure")
		},
	}

	object, err := viewer.ReadObjectExactVersion(context.Background(), evidenceAccess(database.ActorKindHuman), "ws_exact_0001", "frag_exact_0001", "src_ver_old_0001")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("post-admission exact object failure = %v, want ErrNotFound", err)
	}
	if object.Text != nil || object.Fragment.FragmentID != "" {
		t.Fatalf("partial exact object leaked: %#v", object)
	}
	if len(sink.appended) != 2 || sink.appended[0].Action != audit.ActionEvidenceReadAdmitted || sink.appended[1].Action != audit.ActionEvidenceReadFailed {
		t.Fatalf("events = %#v, want admission then failure", sink.appended)
	}
}
