package question

// Card D-17 result 1 and 2: the server-rendered off_topic and vague answers.
// These tests pin the shape that does not depend on the model: at most two
// sentences naming a real subject for off_topic, and exactly one question of
// at most 400 characters offering real options for vague. Recognition is
// measured separately on the real model (ADR-0099 decision 3); nothing here
// proves recognition.

import (
	"regexp"
	"strings"
	"testing"
	"unicode"
)

// shortKindTestSubjects are the synthetic workspace's own human source names,
// the same shape toolLoopOverviewSourceNames returns from knowvault_sources.
var shortKindTestSubjects = []string{"Договоры", "Клиенты", "МНО"}

// shortKindTestSentenceCount mirrors the question set's max_sentences rule:
// text is split on sentence punctuation.
func shortKindTestSentenceCount(text string) int {
	count := 0
	for _, part := range regexp.MustCompile(`[.!?…]+`).Split(strings.ReplaceAll(text, "\n", " "), -1) {
		if strings.TrimSpace(part) != "" {
			count++
		}
	}
	return count
}

// shortKindTestCyrillicRatio mirrors the question set's language rule.
func shortKindTestCyrillicRatio(text string) float64 {
	cyrillic, letters := 0, 0
	for _, r := range text {
		if !unicode.IsLetter(r) {
			continue
		}
		letters++
		if unicode.Is(unicode.Cyrillic, r) {
			cyrillic++
		}
	}
	if letters == 0 {
		return 0
	}
	return float64(cyrillic) / float64(letters)
}

func TestShortKindOffTopicAnswerShape(t *testing.T) {
	answer := renderShortKindAnswer(AnswerKindOffTopic, questionLanguageRussian, shortKindTestSubjects)
	if sentences := shortKindTestSentenceCount(answer); sentences > 2 {
		t.Fatalf("off_topic answer has %d sentences, want at most 2: %q", sentences, answer)
	}
	if !strings.Contains(answer, "не относится") {
		t.Fatalf("off_topic answer does not say the question is outside the workspace: %q", answer)
	}
	named := 0
	for _, subject := range shortKindTestSubjects {
		if strings.Contains(answer, subject) {
			named++
		}
	}
	if named == 0 {
		t.Fatalf("off_topic answer names nothing the workspace holds: %q", answer)
	}
	if strings.Contains(answer, ":") {
		t.Fatalf("off_topic answer contains a colon: %q", answer)
	}
}

func TestShortKindVagueAnswerShape(t *testing.T) {
	answer := renderShortKindAnswer(AnswerKindVague, questionLanguageRussian, shortKindTestSubjects)
	if marks := strings.Count(answer, "?"); marks != 1 {
		t.Fatalf("vague answer has %d question marks, want exactly 1: %q", marks, answer)
	}
	if length := len([]rune(answer)); length > shortKindVagueMaxRunes {
		t.Fatalf("vague answer has %d characters, want at most %d: %q", length, shortKindVagueMaxRunes, answer)
	}
	named := 0
	for _, subject := range shortKindTestSubjects {
		if strings.Contains(answer, subject) {
			named++
		}
	}
	if named < 2 {
		t.Fatalf("vague answer offers %d concrete options, want at least 2: %q", named, answer)
	}
	if strings.Contains(answer, ":") {
		t.Fatalf("vague answer contains a colon: %q", answer)
	}
}

func TestShortKindEnglishAnswerStaysEnglish(t *testing.T) {
	for _, kind := range []AnswerKind{AnswerKindOffTopic, AnswerKindVague} {
		answer := renderShortKindAnswer(kind, questionLanguageEnglish, shortKindTestSubjects)
		if ratio := shortKindTestCyrillicRatio(answer); ratio > 0.3 {
			t.Fatalf("%s English answer has cyrillic ratio %.2f, want at most 0.30: %q", kind, ratio, answer)
		}
		if kind == AnswerKindVague && strings.Count(answer, "?") != 1 {
			t.Fatalf("English vague answer has %d question marks, want exactly 1: %q", strings.Count(answer, "?"), answer)
		}
		if kind == AnswerKindOffTopic && shortKindTestSentenceCount(answer) > 2 {
			t.Fatalf("English off_topic answer has %d sentences, want at most 2: %q", shortKindTestSentenceCount(answer), answer)
		}
	}
}

// The synthetic workspace's sources carry long Cyrillic human names. An
// English answer copies them, so it must prefer the short ones and still name
// a real subject without violating the English language rule.
func TestShortKindEnglishAnswerWithRealSourceNames(t *testing.T) {
	subjects := []string{"Регламенты и договоры", "Клиенты", "Договоры", "МНО"}
	for _, kind := range []AnswerKind{AnswerKindOffTopic, AnswerKindVague} {
		answer := renderShortKindAnswer(kind, questionLanguageEnglish, subjects)
		if ratio := shortKindTestCyrillicRatio(answer); ratio > 0.3 {
			t.Fatalf("%s English answer with real source names has cyrillic ratio %.2f: %q", kind, ratio, answer)
		}
		named := false
		for _, subject := range subjects {
			if strings.Contains(answer, subject) {
				named = true
				break
			}
		}
		if !named {
			t.Fatalf("%s English answer names no real source: %q", kind, answer)
		}
	}
}

func TestShortKindAnswerWithoutSubjectsStillAnswers(t *testing.T) {
	offTopic := renderShortKindAnswer(AnswerKindOffTopic, questionLanguageRussian, nil)
	if strings.TrimSpace(offTopic) == "" || shortKindTestSentenceCount(offTopic) > 2 {
		t.Fatalf("off_topic answer without subjects = %q", offTopic)
	}
	vague := renderShortKindAnswer(AnswerKindVague, questionLanguageRussian, nil)
	if strings.Count(vague, "?") != 1 || len([]rune(vague)) > shortKindVagueMaxRunes {
		t.Fatalf("vague answer without subjects = %q", vague)
	}
}

// Only the two kinds this file owns render; a full question must never receive
// a short-answer template.
func TestShortKindAnswerOnlyRendersOwnKinds(t *testing.T) {
	for _, kind := range []AnswerKind{AnswerKindFull, AnswerKindChange, AnswerKindPlainOverview, ""} {
		if answer := renderShortKindAnswer(kind, questionLanguageRussian, shortKindTestSubjects); answer != "" {
			t.Fatalf("renderShortKindAnswer(%q) = %q, want empty", kind, answer)
		}
	}
}

// The option list is bounded and each name bounded, so a workspace with many or
// long names still yields a short, well-formed answer.
func TestShortKindOptionListIsBounded(t *testing.T) {
	many := []string{"Договоры", "Клиенты", "МНО", "Склады", "Перевозки", strings.Repeat("я", shortKindMaxNameRunes+1)}
	answer := renderShortKindAnswer(AnswerKindVague, questionLanguageRussian, many)
	if len([]rune(answer)) > shortKindVagueMaxRunes || strings.Count(answer, "?") != 1 {
		t.Fatalf("vague answer for many subjects is malformed: %q", answer)
	}
	if strings.Contains(answer, strings.Repeat("я", shortKindMaxNameRunes+1)) {
		t.Fatalf("vague answer copied an overlong subject name: %q", answer)
	}
	offTopic := renderShortKindAnswer(AnswerKindOffTopic, questionLanguageRussian, many)
	if shortKindTestSentenceCount(offTopic) > 2 {
		t.Fatalf("off_topic answer for many subjects has too many sentences: %q", offTopic)
	}
}
