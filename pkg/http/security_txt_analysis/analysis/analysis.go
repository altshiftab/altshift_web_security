// Package analysis says what is wrong with the security.txt a host serves.
//
// It opens no sockets: everything it reports comes from a retrieval.Retrieval, so a
// test builds one and asserts on the findings. A check that passes says nothing, and
// a check that could not be run says so rather than staying quiet -- silence would be
// read as a pass.
package analysis

import (
	"fmt"
	"strings"
	"time"

	"github.com/altshiftab/altshift_web_security/pkg/http/security_txt_analysis/retrieval"
	"github.com/altshiftab/altshift_web_security/pkg/http/security_txt_analysis/rule_id"
	"github.com/altshiftab/altshift_web_security/pkg/http/security_txt_analysis/rule_id_mappings"
	"github.com/altshiftab/utils_go/pkg/http/types/security_txt"
	"github.com/altshiftab/utils_go/pkg/sarif"
)

const (
	ToolName           = "security_txt_checker"
	ToolInformationUri = "https://github.com/altshiftab/altshift_web_security"
)

// RecommendedValidity is how far ahead RFC 9116 section 2.5.5 recommends an Expires
// be set: "less than a year into the future to avoid staleness".
const RecommendedValidity = 365 * 24 * time.Hour

// subjectProperty names the property a report heads a finding with.
const subjectProperty = "subject"

// Analyze reports on what a retrieval found.
func Analyze(found *retrieval.Retrieval) (*sarif.Run, error) {
	if found == nil {
		return nil, nil
	}

	var results []*sarif.Result

	results = append(results, analyzeService(found)...)
	results = append(results, analyzeContents(found)...)

	return &sarif.Run{
		Tool: &sarif.Tool{
			Driver: &sarif.ToolComponent{
				Name:           ToolName,
				InformationUri: ToolInformationUri,
				Rules:          buildRules(results),
			},
		},
		Results: results,
	}, nil
}

// analyzeService reports on how the file was served, which RFC 9116 section 3 has as
// much to say about as it does about the contents.
func analyzeService(found *retrieval.Retrieval) []*sarif.Result {
	if found.Found == nil {
		// Nothing was served. Everything below has no subject, and saying so for
		// each would bury the one finding that matters.
		return []*sarif.Result{
			withProperty(makeResult(rule_id.Missing), "attempted", attemptedUrls(found)),
		}
	}

	var results []*sarif.Result

	if !found.Found.WellKnown {
		results = append(
			results,
			withProperty(makeResult(rule_id.NotAtWellKnownPath), "url", found.Found.Url),
		)
	}

	if !found.ServedOverHttps() {
		results = append(
			results,
			withProperty(makeResult(rule_id.NotHttps), "url", found.Found.FinalUrl),
		)
	}

	if !found.ContentTypeIsPlainUtf8() {
		contentType := found.Found.ContentType
		if contentType == "" {
			contentType = "none"
		}

		results = append(
			results,
			withProperty(makeResult(rule_id.BadContentType), "contentType", contentType),
		)
	}

	return results
}

// analyzeContents reports on what the file says.
func analyzeContents(found *retrieval.Retrieval) []*sarif.Result {
	if found.Found == nil {
		return nil
	}

	if found.Parsed == nil {
		reason := found.ParseError
		if reason == "" {
			reason = "the file was not parsed"
		}

		return []*sarif.Result{withProperty(makeResult(rule_id.SyntaxError), "reason", reason)}
	}

	var results []*sarif.Result

	results = append(results, analyzeMalformedFields(found.Parsed)...)
	results = append(results, analyzeRequiredFields(found)...)
	results = append(results, analyzeRepeatedFields(found.Parsed)...)
	results = append(results, analyzeCanonical(found)...)

	return results
}

func analyzeMalformedFields(parsed *security_txt.Parsed) []*sarif.Result {
	var results []*sarif.Result

	for _, field := range parsed.Fields {
		if !field.Malformed {
			continue
		}

		result := withMessage(
			makeResult(rule_id.MalformedField),
			fmt.Sprintf(
				"The %s field on line %d has the value %q, which is not what RFC 9116 requires of that field. "+
					"A conforming reader skips it, so whatever it was meant to say goes unsaid.",
				field.Name,
				field.Line,
				field.Value,
			),
		)

		results = append(
			results,
			withProperty(withProperty(withProperty(result, "field", field.Name), "line", field.Line), "value", field.Value),
		)
	}

	return results
}

func analyzeRequiredFields(found *retrieval.Retrieval) []*sarif.Result {
	parsed := found.Parsed

	var results []*sarif.Result

	if len(parsed.SecurityTxt.Contacts) == 0 {
		results = append(results, makeResult(rule_id.MissingContact))
	}

	expires := parsed.SecurityTxt.Expires
	if expires.IsZero() {
		return append(results, makeResult(rule_id.MissingExpires))
	}

	now := found.Now
	if now.IsZero() {
		now = time.Now()
	}

	switch {
	case expires.Before(now):
		results = append(
			results,
			withProperty(
				withMessage(
					makeResult(rule_id.Expired),
					fmt.Sprintf(
						"The security.txt expired on %s. RFC 9116 section 2.5.5 has a reader disregard a file whose "+
							"Expires has passed, so the host is in the same position as one serving none at all -- "+
							"while appearing, to anyone glancing at it, to have the matter in hand.",
						expires.UTC().Format(time.RFC3339),
					),
				),
				"expires",
				expires.UTC().Format(time.RFC3339),
			),
		)
	case expires.After(now.Add(RecommendedValidity)):
		results = append(
			results,
			withProperty(makeResult(rule_id.ExpiresTooDistant), "expires", expires.UTC().Format(time.RFC3339)),
		)
	}

	return results
}

func analyzeRepeatedFields(parsed *security_txt.Parsed) []*sarif.Result {
	var results []*sarif.Result

	for _, entry := range []struct {
		field  string
		ruleId string
	}{
		{field: security_txt.FieldExpires, ruleId: rule_id.MultipleExpires},
		{field: security_txt.FieldPreferredLanguages, ruleId: rule_id.MultiplePreferredLanguages},
	} {
		fields := parsed.Get(entry.field)
		if len(fields) < 2 {
			continue
		}

		lines := make([]int, 0, len(fields))
		for _, field := range fields {
			lines = append(lines, field.Line)
		}

		results = append(
			results,
			withProperty(withProperty(makeResult(entry.ruleId), "count", len(fields)), "lines", lines),
		)
	}

	return results
}

// analyzeCanonical reports a file whose Canonical fields do not name where it was
// found. RFC 9116 section 2.5.2 says the contents should not then be trusted.
func analyzeCanonical(found *retrieval.Retrieval) []*sarif.Result {
	canonical := found.Parsed.SecurityTxt.Canonical
	if len(canonical) == 0 {
		// The field is optional, and without it there is nothing to mismatch.
		return nil
	}

	retrievedFrom := found.Found.FinalUrl
	if retrievedFrom == "" {
		retrievedFrom = found.Found.Url
	}

	for _, candidate := range canonical {
		if strings.EqualFold(strings.TrimRight(candidate, "/"), strings.TrimRight(retrievedFrom, "/")) {
			return nil
		}
	}

	return []*sarif.Result{
		withProperty(
			withProperty(
				withMessage(
					makeResult(rule_id.CanonicalMismatch),
					fmt.Sprintf(
						"The security.txt was retrieved from %s, and lists as canonical only %s. RFC 9116 section "+
							"2.5.2 says that in this case the contents SHOULD NOT be trusted: the field exists so "+
							"that a copy planted elsewhere can be told from the genuine one.",
						retrievedFrom,
						strings.Join(canonical, ", "),
					),
				),
				"retrievedFrom",
				retrievedFrom,
			),
			"canonical",
			canonical,
		),
	}
}

func attemptedUrls(found *retrieval.Retrieval) []string {
	urls := make([]string, 0, len(found.Attempts))
	for _, attempt := range found.Attempts {
		urls = append(urls, attempt.Url)
	}

	return urls
}

// severityToLevel maps the policy's severity vocabulary onto SARIF levels.
func severityToLevel(severity rule_id_mappings.Severity) sarif.Level {
	switch severity {
	case rule_id_mappings.SeverityMedium:
		return sarif.LevelWarning
	case rule_id_mappings.SeverityLow:
		return sarif.LevelNote
	case rule_id_mappings.SeverityInfo:
		return sarif.LevelNone
	default:
		return sarif.LevelNone
	}
}

func makeResult(ruleId string) *sarif.Result {
	return &sarif.Result{
		RuleId:  ruleId,
		Kind:    sarif.KindFail,
		Level:   severityToLevel(rule_id_mappings.RuleIdToSeverity[ruleId]),
		Message: &sarif.Message{Text: rule_id_mappings.RuleIdToDescription[ruleId]},
		Properties: sarif.PropertyBag{
			subjectProperty: rule_id_mappings.RuleIdToTitle[ruleId],
		},
	}
}

func withProperty(result *sarif.Result, name string, value any) *sarif.Result {
	if result == nil {
		return nil
	}

	if result.Properties == nil {
		result.Properties = sarif.PropertyBag{}
	}

	result.Properties[name] = value

	return result
}

func withMessage(result *sarif.Result, text string) *sarif.Result {
	if result == nil {
		return nil
	}

	result.Message = &sarif.Message{Text: text}

	return result
}

func buildRules(results []*sarif.Result) []*sarif.ReportingDescriptor {
	seen := map[string]bool{}

	var rules []*sarif.ReportingDescriptor

	for _, result := range results {
		if result == nil || result.RuleId == "" || seen[result.RuleId] {
			continue
		}

		seen[result.RuleId] = true

		rule := &sarif.ReportingDescriptor{Id: result.RuleId}

		if title := rule_id_mappings.RuleIdToTitle[result.RuleId]; title != "" {
			rule.ShortDescription = &sarif.MultiformatMessageString{Text: title}
		}

		if description := rule_id_mappings.RuleIdToDescription[result.RuleId]; description != "" {
			rule.FullDescription = &sarif.MultiformatMessageString{Text: description}
		}

		rules = append(rules, rule)
	}

	return rules
}
