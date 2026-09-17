package question

import (
	"encoding/json"
	"regexp"
	"testing"
)

func TestGenerationTextSchemaRejectsControlCharacters(t *testing.T) {
	var schema struct {
		Properties struct {
			Claims struct {
				Items struct {
					Properties struct {
						Text struct {
							Pattern string `json:"pattern"`
						} `json:"text"`
					} `json:"properties"`
				} `json:"items"`
			} `json:"claims"`
		} `json:"properties"`
	}
	if err := json.Unmarshal([]byte(generationOutputSchema), &schema); err != nil {
		t.Fatal(err)
	}
	pattern := schema.Properties.Claims.Items.Properties.Text.Pattern
	if pattern == "" {
		t.Fatal("claim text schema has no control-character constraint")
	}
	allowed := regexp.MustCompile(pattern)
	for _, value := range []string{"\u041f\u0440\u043e\u0432\u0435\u0440\u044c\u0442\u0435 \u043c\u0430\u0440\u0448\u0440\u0443\u0442.", "\u0412 \u0438\u0441\u0442\u043e\u0447\u043d\u0438\u043a\u0430\u0445 \u0443\u043a\u0430\u0437\u0430\u043d\u044b \u0440\u0430\u0437\u043d\u044b\u0435 \u0441\u0440\u043e\u043a\u0438: 2 \u0447\u0430\u0441\u0430 \u0438 4 \u0447\u0430\u0441\u0430."} {
		if !allowed.MatchString(value) {
			t.Fatalf("single-line claim rejected: %q", value)
		}
	}
	for _, value := range []string{"", "\u043f\u0435\u0440\u0432\u044b\u0439\n\u0432\u0442\u043e\u0440\u043e\u0439", "\u043f\u0435\u0440\u0432\u044b\u0439\r\u0432\u0442\u043e\u0440\u043e\u0439", "\u043f\u0435\u0440\u0432\u044b\u0439\t\u0432\u0442\u043e\u0440\u043e\u0439", "\u0442\u0435\u043a\u0441\u0442\x00", "\u0442\u0435\u043a\u0441\u0442\x7f", "\u0442\u0435\u043a\u0441\u0442\u0085"} {
		if allowed.MatchString(value) {
			t.Fatalf("invalid claim text accepted: %q", value)
		}
	}
}
