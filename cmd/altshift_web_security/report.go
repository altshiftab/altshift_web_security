package main

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/altshiftab/utils_go/pkg/sarif"
)

// reportWidth is the column the report wraps at. It is fixed rather than taken from the terminal so
// that what a run writes does not depend on the window it was run in, a report being something that
// gets pasted and compared.
const reportWidth = 92

// indent is the gutter the level occupies, which everything under a finding lines up against.
const indent = "          "

// levelRank orders the SARIF levels by how much they are worth reading, which is what --min-level
// withholds against and what the report sorts on. The library ranks them for its own purposes
// behind an internal package; this is the same order, held where a caller can reach it.
var levelRank = map[sarif.Level]int{
	sarif.LevelNone:    0,
	sarif.LevelNote:    1,
	sarif.LevelWarning: 2,
	sarif.LevelError:   3,
}

// parseLevel reads a level from what was typed. The parser has already restricted the option to its
// choices, so anything else is an option that went unset, which withholds nothing.
func parseLevel(value string) sarif.Level {
	level := sarif.Level(value)
	if _, found := levelRank[level]; !found {
		return sarif.LevelNone
	}

	return level
}

func filterResults(results []*sarif.Result, minLevel sarif.Level) []*sarif.Result {
	minRank := levelRank[minLevel]

	filtered := make([]*sarif.Result, 0, len(results))
	for _, result := range results {
		if result == nil || levelRank[result.Level] < minRank {
			continue
		}

		filtered = append(filtered, result)
	}

	if len(filtered) == 0 {
		return nil
	}

	return filtered
}

// sortResults puts the worst first. It sorts in place and keeps the order the analysis produced
// within a level, which is the order of the header names it walked.
func sortResults(results []*sarif.Result) {
	sort.SliceStable(results, func(i int, j int) bool {
		return levelRank[results[i].Level] > levelRank[results[j].Level]
	})
}

// pruneRules drops the rules that describe nothing, which is what filtering results leaves behind.
func pruneRules(rules []*sarif.ReportingDescriptor, results []*sarif.Result) []*sarif.ReportingDescriptor {
	if len(rules) == 0 {
		return nil
	}

	raised := make(map[string]bool, len(results))
	for _, result := range results {
		if result != nil {
			raised[result.RuleId] = true
		}
	}

	pruned := make([]*sarif.ReportingDescriptor, 0, len(rules))
	for _, rule := range rules {
		if rule == nil || !raised[rule.Id] {
			continue
		}

		pruned = append(pruned, rule)
	}

	if len(pruned) == 0 {
		return nil
	}

	return pruned
}

// headerProperty reads back what the analysis recorded about where a finding came from. The
// properties are a bag of anything, so a value that is not a string is treated as absent rather
// than printed as whatever it is.
func headerProperty(result *sarif.Result, name string) string {
	if result == nil || result.Properties == nil {
		return ""
	}

	value, _ := result.Properties[name].(string)

	return value
}

// writeReport writes the findings for a person to read: the level and the header it is about, then
// the reason, then the value it was raised on. A finding is a paragraph rather than a line because
// the reason is the part worth having, and it does not fit on one.
func writeReport(writer io.Writer, results []*sarif.Result) error {
	if len(results) == 0 {
		if _, err := fmt.Fprintln(writer, "No findings."); err != nil {
			return fmt.Errorf("fprintln: %w", err)
		}

		return nil
	}

	for i, result := range results {
		if result == nil {
			continue
		}

		if i != 0 {
			if _, err := fmt.Fprintln(writer); err != nil {
				return fmt.Errorf("fprintln: %w", err)
			}
		}

		// What a finding is about: the header it was raised on, or -- for the
		// checks that are not about a header at all -- whatever the analysis named
		// as the subject.
		subject := headerProperty(result, "subject")
		if subject == "" {
			subject = headerProperty(result, "headerName")
		}

		heading := fmt.Sprintf("%-9s %s", result.Level, subject)
		if result.RuleId != "" {
			heading = strings.TrimRight(heading, " ") + "  (" + result.RuleId + ")"
		}

		if _, err := fmt.Fprintln(writer, heading); err != nil {
			return fmt.Errorf("fprintln: %w", err)
		}

		if result.Message != nil {
			for _, line := range wrap(result.Message.Text, reportWidth-len(indent)) {
				if _, err := fmt.Fprintln(writer, indent+line); err != nil {
					return fmt.Errorf("fprintln: %w", err)
				}
			}
		}

		// The value is context for the reason above it rather than something to read in full, and a
		// policy raising eight findings would otherwise print itself under each of them. It gets
		// one line; --json has it whole.
		if value := headerProperty(result, "headerValue"); value != "" {
			line := "value: " + truncate(value, reportWidth-len(indent)-len("value: "))
			if _, err := fmt.Fprintln(writer, indent+line); err != nil {
				return fmt.Errorf("fprintln: %w", err)
			}
		}
	}

	return nil
}

// truncate cuts text to width, marking that it was cut. A width too small to say anything in
// returns the ellipsis alone rather than a negative slice.
func truncate(text string, width int) string {
	runes := []rune(text)
	if len(runes) <= width {
		return text
	}

	if width <= 1 {
		return "…"
	}

	return strings.TrimRight(string(runes[:width-1]), " ") + "…"
}

// wrap breaks text into lines no longer than width, on the spaces between words. A word longer than
// the width is left whole and overruns: breaking a URL or a policy source in half to fit would cost
// more than the overrun does.
func wrap(text string, width int) []string {
	fields := strings.Fields(text)
	if len(fields) == 0 {
		return nil
	}

	if width <= 0 {
		return fields
	}

	var lines []string
	current := fields[0]

	for _, field := range fields[1:] {
		if len(current)+1+len(field) > width {
			lines = append(lines, current)
			current = field

			continue
		}

		current += " " + field
	}

	return append(lines, current)
}
