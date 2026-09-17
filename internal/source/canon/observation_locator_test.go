package canon

import (
	"bytes"
	"testing"
)

func TestObservationLocatorSeparatesExternalAndNestedIdentity(t *testing.T) {
	external, err := ObservationExternalIDBytes("conn_1", "MAIL", "imap:box;uid:7")
	if err != nil {
		t.Fatalf("external id: %v", err)
	}
	flat, err := ObservationLocatorBytes("conn_1", "MAIL", "imap:box;uid:7", "", "")
	if err != nil {
		t.Fatalf("flat locator: %v", err)
	}
	nested, err := ObservationLocatorBytes("conn_1", "MAIL", "imap:box;uid:7;part:2", "imap:box;uid:7", "2")
	if err != nil {
		t.Fatalf("nested locator: %v", err)
	}
	if bytes.Equal(external, flat) || bytes.Equal(flat, nested) {
		t.Fatal("identity and locator projections must remain distinct")
	}
	if !bytes.Equal(flat, mustCanonicalLocator("conn_1", "MAIL", "imap:box;uid:7", "", "")) {
		t.Fatal("locator projection is not deterministic")
	}
}

func mustCanonicalLocator(connectionID, kind, externalID, parent, part string) []byte {
	value, err := ObservationLocatorBytes(connectionID, kind, externalID, parent, part)
	if err != nil {
		panic(err)
	}
	return value
}
