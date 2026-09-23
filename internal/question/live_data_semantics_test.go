package question

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestLiveDataEmptyIntervalDoesNotBecomeZeroOrCompletePopulation(t *testing.T) {
	for _, example := range []struct {
		name  string
		rows  [][]*string
		state string
	}{
		{"no rows", [][]*string{}, "NO_OBSERVATIONS_RETURNED"},
		{"null aggregate", [][]*string{{nil}}, "QUERY_ROWS_RETURNED"},
	} {
		t.Run(example.name, func(t *testing.T) {
			projection := liveDataProjection{Rows: example.rows, RowCount: len(example.rows), Complete: true}
			payload, err := liveDataModelPayload(projection)
			if err != nil {
				t.Fatal(err)
			}
			var got struct {
				Rows           [][]*string `json:"rows"`
				Coverage       string      `json:"population_coverage"`
				State          string      `json:"observation_state"`
				Interpretation string      `json:"interpretation"`
			}
			if json.Unmarshal(payload, &got) != nil || got.Coverage != "UNKNOWN" || got.State != example.state ||
				!strings.Contains(got.Interpretation, "do not establish a numeric zero") ||
				!strings.Contains(got.Interpretation, "completeness remain unknown") {
				t.Fatalf("unsafe empty-result interpretation: %s", payload)
			}
			if len(got.Rows) != len(example.rows) || (len(got.Rows) > 0 && got.Rows[0][0] != nil) {
				t.Fatal("missing observation was replaced by a numeric value")
			}
			// Semantics added for model context must not alter the sealed receipt.
			stored, _ := json.Marshal(projection)
			if strings.Contains(string(stored), "population_coverage") {
				t.Fatal("interpretation changed the historical observation format")
			}
		})
	}
}
