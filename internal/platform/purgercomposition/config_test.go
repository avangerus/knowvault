package purgercomposition

import "testing"

func TestLoadProductionRejectsUnknownAndDuplicateEnvironment(t *testing.T) {
	valid := []string{
		"KNOWVAULT_ORGANIZATION_ID=org_001",
		"KNOWVAULT_PROVIDER_ID=provider_001",
		"KNOWVAULT_PURGER_ID=purger_001",
		"KNOWVAULT_PURGER_LEASE_SECONDS=60",
		"KNOWVAULT_PURGER_POLL_SECONDS=2",
	}
	if config, err := loadProduction(valid); err != nil || config.PurgerID() != "purger_001" {
		t.Fatalf("valid config=%#v err=%v", config, err)
	}
	for name, extra := range map[string]string{
		"unknown":        "KNOWVAULT_HTTP_ADDR=127.0.0.1:8080",
		"case duplicate": "knowvault_purger_id=purger_002",
		"malformed":      "KNOWVAULT_BROKEN",
	} {
		t.Run(name, func(t *testing.T) {
			candidate := append([]string(nil), valid...)
			candidate = append(candidate, extra)
			if _, err := loadProduction(candidate); CodeOf(err) != CodeConfigInvalid {
				t.Fatalf("config accepted: err=%v", err)
			}
		})
	}
}

func TestLoadProductionRejectsUnsafeLeaseProfile(t *testing.T) {
	base := []string{
		"KNOWVAULT_ORGANIZATION_ID=org_001",
		"KNOWVAULT_PROVIDER_ID=provider_001",
		"KNOWVAULT_PURGER_ID=purger_001",
		"KNOWVAULT_PURGER_LEASE_SECONDS=60",
		"KNOWVAULT_PURGER_POLL_SECONDS=2",
	}
	for index, value := range map[int]string{
		3: "KNOWVAULT_PURGER_LEASE_SECONDS=2",
		4: "KNOWVAULT_PURGER_POLL_SECONDS=60",
	} {
		candidate := append([]string(nil), base...)
		candidate[index] = value
		if _, err := loadProduction(candidate); CodeOf(err) != CodeConfigInvalid {
			t.Fatalf("unsafe profile %q accepted: err=%v", value, err)
		}
	}
}
