package analytic

import (
	"sort"
	"strings"
	"unicode/utf8"
)

// Bounds for a semantics value. They are deliberately small and fixed so a
// defended request cannot inflate the analytic working set.
const (
	semanticsMinFields       = 1
	semanticsMaxFields       = 256
	semanticsMinMeasures     = 1
	semanticsMaxMeasures     = 128
	semanticsMaxAliases      = 8
	semanticsMaxShortString  = 160
	semanticsMaxLongString   = 1024
	semanticsMaxIdentitySize = 256
)

// FieldSemanticsInput is a detached caller-supplied field semantics value.
type FieldSemanticsInput struct {
	Token       string
	Label       string
	Description string
	NullMeaning string
	Aliases     []string
}

// MeasureSemanticsInput is a detached caller-supplied measure semantics value.
type MeasureSemanticsInput struct {
	ID          string
	Label       string
	Description string
	Aliases     []string
}

// ProfileSemanticsInput is a detached caller-supplied semantics value.
type ProfileSemanticsInput struct {
	DatasetLabel       string
	DatasetDescription string
	Fields             []FieldSemanticsInput
	Measures           []MeasureSemanticsInput
}

// ProfileSemantics is an immutable, internally validated business semantics
// value. Fields are unexported so the only way to obtain a value is the
// constructor, and Valid revalidates the stored content.
type ProfileSemantics struct {
	datasetLabel       string
	datasetDescription string
	fields             []storedFieldSemantics
	measures           []storedMeasureSemantics
}

type storedFieldSemantics struct {
	token       string
	label       string
	description string
	nullMeaning string
	aliases     []string
}

type storedMeasureSemantics struct {
	id          string
	label       string
	description string
	aliases     []string
}

// NewProfileSemantics validates every human string, canonicalizes ordering,
// and stores privately owned copies of all slices.
func NewProfileSemantics(input ProfileSemanticsInput) (ProfileSemantics, error) {
	if len(input.Fields) < semanticsMinFields || len(input.Fields) > semanticsMaxFields {
		return ProfileSemantics{}, invalidProfileSemantics()
	}
	if len(input.Measures) < semanticsMinMeasures || len(input.Measures) > semanticsMaxMeasures {
		return ProfileSemantics{}, invalidProfileSemantics()
	}
	if !validSemanticsString(input.DatasetLabel, semanticsMaxShortString) {
		return ProfileSemantics{}, invalidProfileSemantics()
	}
	if !validSemanticsString(input.DatasetDescription, semanticsMaxLongString) {
		return ProfileSemantics{}, invalidProfileSemantics()
	}

	fields := make([]storedFieldSemantics, 0, len(input.Fields))
	for _, field := range input.Fields {
		converted, ok := storedSemanticsField(field)
		if !ok {
			return ProfileSemantics{}, invalidProfileSemantics()
		}
		fields = append(fields, converted)
	}
	sort.Slice(fields, func(left, right int) bool { return fields[left].token < fields[right].token })
	for index := 1; index < len(fields); index++ {
		if fields[index].token == fields[index-1].token {
			return ProfileSemantics{}, invalidProfileSemantics()
		}
	}

	measures := make([]storedMeasureSemantics, 0, len(input.Measures))
	for _, measure := range input.Measures {
		converted, ok := storedSemanticsMeasure(measure)
		if !ok {
			return ProfileSemantics{}, invalidProfileSemantics()
		}
		measures = append(measures, converted)
	}
	sort.Slice(measures, func(left, right int) bool { return measures[left].id < measures[right].id })
	for index := 1; index < len(measures); index++ {
		if measures[index].id == measures[index-1].id {
			return ProfileSemantics{}, invalidProfileSemantics()
		}
	}

	return ProfileSemantics{
		datasetLabel:       input.DatasetLabel,
		datasetDescription: input.DatasetDescription,
		fields:             fields,
		measures:           measures,
	}, nil
}

// Valid revalidates the whole stored value. A zero value, a forged value
// written inside the package, or a value assembled without the constructor
// must all fail.
func (value ProfileSemantics) Valid() bool {
	if len(value.fields) < semanticsMinFields || len(value.fields) > semanticsMaxFields {
		return false
	}
	if len(value.measures) < semanticsMinMeasures || len(value.measures) > semanticsMaxMeasures {
		return false
	}
	if !validSemanticsString(value.datasetLabel, semanticsMaxShortString) {
		return false
	}
	if !validSemanticsString(value.datasetDescription, semanticsMaxLongString) {
		return false
	}

	for index, field := range value.fields {
		if !validSemanticsToken(field.token) {
			return false
		}
		if !validSemanticsString(field.label, semanticsMaxShortString) {
			return false
		}
		if !validSemanticsString(field.description, semanticsMaxLongString) {
			return false
		}
		if !validSemanticsString(field.nullMeaning, semanticsMaxLongString) {
			return false
		}
		if !validSemanticsAliases(field.aliases, field.label) {
			return false
		}
		if index > 0 && value.fields[index-1].token >= field.token {
			return false
		}
	}

	for index, measure := range value.measures {
		if !validProfileIdentity(measure.id) {
			return false
		}
		if !validSemanticsString(measure.label, semanticsMaxShortString) {
			return false
		}
		if !validSemanticsString(measure.description, semanticsMaxLongString) {
			return false
		}
		if !validSemanticsAliases(measure.aliases, measure.label) {
			return false
		}
		if index > 0 && value.measures[index-1].id >= measure.id {
			return false
		}
	}

	return true
}

// Values returns a fully detached copy of the stored semantics.
func (value ProfileSemantics) Values() ProfileSemanticsInput {
	fields := make([]FieldSemanticsInput, 0, len(value.fields))
	for _, field := range value.fields {
		fields = append(fields, FieldSemanticsInput{
			Token:       field.token,
			Label:       field.label,
			Description: field.description,
			NullMeaning: field.nullMeaning,
			Aliases:     cloneSemanticsStrings(field.aliases),
		})
	}
	measures := make([]MeasureSemanticsInput, 0, len(value.measures))
	for _, measure := range value.measures {
		measures = append(measures, MeasureSemanticsInput{
			ID:          measure.id,
			Label:       measure.label,
			Description: measure.description,
			Aliases:     cloneSemanticsStrings(measure.aliases),
		})
	}
	return ProfileSemanticsInput{
		DatasetLabel:       value.datasetLabel,
		DatasetDescription: value.datasetDescription,
		Fields:             fields,
		Measures:           measures,
	}
}

func storedSemanticsField(input FieldSemanticsInput) (storedFieldSemantics, bool) {
	if !validSemanticsToken(input.Token) {
		return storedFieldSemantics{}, false
	}
	if !validSemanticsString(input.Label, semanticsMaxShortString) {
		return storedFieldSemantics{}, false
	}
	if !validSemanticsString(input.Description, semanticsMaxLongString) {
		return storedFieldSemantics{}, false
	}
	if !validSemanticsString(input.NullMeaning, semanticsMaxLongString) {
		return storedFieldSemantics{}, false
	}
	aliases, ok := storedSemanticsAliases(input.Aliases, input.Label)
	if !ok {
		return storedFieldSemantics{}, false
	}
	return storedFieldSemantics{
		token:       input.Token,
		label:       input.Label,
		description: input.Description,
		nullMeaning: input.NullMeaning,
		aliases:     aliases,
	}, true
}

func storedSemanticsMeasure(input MeasureSemanticsInput) (storedMeasureSemantics, bool) {
	if !validProfileIdentity(input.ID) {
		return storedMeasureSemantics{}, false
	}
	if !validSemanticsString(input.Label, semanticsMaxShortString) {
		return storedMeasureSemantics{}, false
	}
	if !validSemanticsString(input.Description, semanticsMaxLongString) {
		return storedMeasureSemantics{}, false
	}
	aliases, ok := storedSemanticsAliases(input.Aliases, input.Label)
	if !ok {
		return storedMeasureSemantics{}, false
	}
	return storedMeasureSemantics{
		id:          input.ID,
		label:       input.Label,
		description: input.Description,
		aliases:     aliases,
	}, true
}

func storedSemanticsAliases(aliases []string, label string) ([]string, bool) {
	if !validSemanticsAliases(aliases, label) {
		return nil, false
	}
	return cloneSemanticsStrings(aliases), true
}

func validSemanticsAliases(aliases []string, label string) bool {
	if len(aliases) > semanticsMaxAliases {
		return false
	}
	for index, alias := range aliases {
		if !validSemanticsString(alias, semanticsMaxShortString) {
			return false
		}
		if strings.EqualFold(alias, label) {
			return false
		}
		for previous := 0; previous < index; previous++ {
			if strings.EqualFold(aliases[previous], alias) {
				return false
			}
		}
	}
	return true
}

func validSemanticsToken(token string) bool {
	return len(token) <= semanticsMaxIdentitySize && fieldTokenPattern.MatchString(token)
}

func validSemanticsString(value string, limit int) bool {
	if len(value) == 0 || len(value) > limit {
		return false
	}
	if !utf8.ValidString(value) {
		return false
	}
	if strings.TrimSpace(value) != value {
		return false
	}
	return !strings.ContainsFunc(value, isUnicodeControl)
}

func isUnicodeControl(character rune) bool {
	return character < 0x20 || (character >= 0x7f && character <= 0x9f)
}

func cloneSemanticsStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	cloned := make([]string, len(values))
	copy(cloned, values)
	return cloned
}

func invalidProfileSemantics() error { return &Error{code: CodeInvalidRequest} }
