package question

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var comparisonDottedDate = regexp.MustCompile(`\b([0-3]?\d)\.([01]?\d)\.(20\d{2})\b`)
var comparisonRepeatedMonth = regexp.MustCompile(`\b([0-3]?\d)\s+([\p{L}]+)\s+(?:and|` + "\u0438" + `)\s+([0-3]?\d)\s+([\p{L}]+)\s+(20\d{2})\b`)

// comparisonDatePair admits only two distinct calendar dates supplied by the
// user. Tool arguments and retrieved material cannot expand this scope.
func comparisonDatePair(question string, history []toolLoopConversationTurn) [2]string {
	dates := explicitComparisonDates(question)
	if len(dates) == 0 && comparisonFollowup(question) && len(history) > 0 {
		// Only the immediately preceding readable user question can supply dates.
		dates = explicitComparisonDates(history[len(history)-1].Question)
	}
	if len(dates) != 2 {
		return [2]string{}
	}
	return [2]string{dates[0], dates[1]}
}

func explicitComparisonDates(question string) []string {
	text := strings.ToLower(question)
	unique := map[string]struct{}{}
	add := func(year, month, day int) {
		candidate := time.Date(year, time.Month(month), day, 0, 0, 0, 0, time.UTC)
		if candidate.Year() == year && int(candidate.Month()) == month && candidate.Day() == day {
			unique[candidate.Format("2006-01-02")] = struct{}{}
		}
	}
	for _, value := range comparisonISODate.FindAllString(text, -1) {
		if date, err := time.Parse("2006-01-02", value); err == nil {
			add(date.Year(), int(date.Month()), date.Day())
		}
	}
	for _, fields := range comparisonDottedDate.FindAllStringSubmatch(text, -1) {
		day, _ := strconv.Atoi(fields[1])
		month, _ := strconv.Atoi(fields[2])
		year, _ := strconv.Atoi(fields[3])
		add(year, month, day)
	}
	for _, fields := range comparisonWrittenDate.FindAllStringSubmatch(text, -1) {
		day, _ := strconv.Atoi(fields[1])
		year, _ := strconv.Atoi(fields[3])
		if month := comparisonMonth(fields[2]); month > 0 {
			add(year, month, day)
		}
	}
	for _, fields := range comparisonSharedMonth.FindAllStringSubmatch(text, -1) {
		first, _ := strconv.Atoi(fields[1])
		second, _ := strconv.Atoi(fields[2])
		year, _ := strconv.Atoi(fields[4])
		if month := comparisonMonth(fields[3]); month > 0 {
			add(year, month, first)
			add(year, month, second)
		}
	}
	for _, fields := range comparisonRepeatedMonth.FindAllStringSubmatch(text, -1) {
		first, _ := strconv.Atoi(fields[1])
		second, _ := strconv.Atoi(fields[3])
		year, _ := strconv.Atoi(fields[5])
		if month := comparisonMonth(fields[2]); month > 0 {
			add(year, month, first)
		}
		if month := comparisonMonth(fields[4]); month > 0 {
			add(year, month, second)
		}
	}
	dates := make([]string, 0, len(unique))
	for value := range unique {
		dates = append(dates, value)
	}
	sort.Strings(dates)
	return dates
}

func comparisonFollowup(question string) bool {
	text := strings.ToLower(question)
	if !hasComparisonCue(text) {
		return false
	}
	for _, marker := range []string{
		"these two days", "those two days", "these two dates", "those two dates",
		"\u044d\u0442\u0438\u0445 \u0434\u0432\u0443\u0445 \u0434\u043d\u0435\u0439",
		"\u044d\u0442\u0438 \u0434\u0432\u0430 \u0434\u043d\u044f",
		"\u044d\u0442\u0438\u0445 \u0434\u0432\u0443\u0445 \u0434\u0430\u0442",
		"\u044d\u0442\u0438 \u0434\u0432\u0435 \u0434\u0430\u0442\u044b",
	} {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

func comparisonArgumentsMatch(raw []byte, pair [2]string) bool {
	if pair == [2]string{} {
		return false
	}
	args, ok := parseTrustedMetricArguments(raw)
	return ok && ((args.DateA == pair[0] && args.DateB == pair[1]) ||
		(args.DateA == pair[1] && args.DateB == pair[0]))
}

func sameSingleDate(dates []string, want string) bool {
	return len(dates) == 1 && dates[0] == want
}
