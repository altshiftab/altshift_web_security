package rule_id_mappings

import (
	"github.com/altshiftab/altshift_web_security/pkg/http/security_txt_analysis/rule_id"
)

// Severity is the qualitative severity a rule carries, mapped onto a SARIF level for
// emission.
//
// Nothing here reaches "high". A security.txt is how a finder is told where to send
// what they have found; getting it wrong wastes a report, and does not let anyone in.
type Severity string

const (
	SeverityMedium Severity = "medium"
	SeverityLow    Severity = "low"
	SeverityInfo   Severity = "info"
)

//nolint:dupl // deliberately parallel static tables; the shared key set is the point.
var RuleIdToSeverity = map[string]Severity{
	rule_id.Missing:            SeverityInfo,
	rule_id.NotAtWellKnownPath: SeverityLow,
	// The one thing here that is a weakness rather than a nuisance: a report sent
	// over an unencrypted channel can be read and altered on the way.
	rule_id.NotHttps:       SeverityMedium,
	rule_id.BadContentType: SeverityInfo,

	rule_id.SyntaxError:    SeverityLow,
	rule_id.MalformedField: SeverityLow,

	rule_id.MissingContact:    SeverityLow,
	rule_id.MissingExpires:    SeverityLow,
	rule_id.Expired:           SeverityLow,
	rule_id.ExpiresTooDistant: SeverityInfo,

	rule_id.MultipleExpires:            SeverityInfo,
	rule_id.MultiplePreferredLanguages: SeverityInfo,

	rule_id.CanonicalMismatch: SeverityLow,

	rule_id.CheckNotDetermined: SeverityInfo,
}

//nolint:dupl // see the note on RuleIdToSeverity.
var RuleIdToTitle = map[string]string{
	rule_id.Missing:            "The host serves no security.txt",
	rule_id.NotAtWellKnownPath: "The security.txt is not at the well-known path",
	rule_id.NotHttps:           "The security.txt is not served over https",
	rule_id.BadContentType:     "The security.txt is not served as text/plain; charset=utf-8",

	rule_id.SyntaxError:    "The security.txt is not syntactically correct",
	rule_id.MalformedField: "A security.txt field has a malformed value",

	rule_id.MissingContact:    "The security.txt has no Contact field",
	rule_id.MissingExpires:    "The security.txt has no Expires field",
	rule_id.Expired:           "The security.txt has expired",
	rule_id.ExpiresTooDistant: "The security.txt expires more than a year from now",

	rule_id.MultipleExpires:            "The security.txt has more than one Expires field",
	rule_id.MultiplePreferredLanguages: "The security.txt has more than one Preferred-Languages field",

	rule_id.CanonicalMismatch: "The security.txt does not list the URI it was retrieved from as canonical",

	rule_id.CheckNotDetermined: "A check could not be completed",
}

var RuleIdToDescription = map[string]string{
	rule_id.Missing:            "The host serves no security.txt. RFC 9116 defines it as the place a researcher looks to find out where to send a vulnerability report and under what terms. Without one, someone who has found a weakness has to guess -- and what they guess is often a public disclosure, a support form that discards it, or nothing at all.",
	rule_id.NotAtWellKnownPath: "The security.txt was found only at the top-level /security.txt. RFC 9116 section 3 requires it under the /.well-known/ path, which is where automated tooling and researchers following the RFC will look; the top-level location predates the standard and is kept only for compatibility. A file only they can find is one most finders will not.",
	rule_id.NotHttps:           "The security.txt was not served over https. RFC 9116 section 3 requires the https scheme. Served without it, the addresses and policy a reporter is told to use can be read and rewritten in transit -- so an attacker can redirect vulnerability reports about this host to themselves.",
	rule_id.BadContentType:     "The security.txt was not served as \"text/plain\" with the charset parameter set to \"utf-8\", which RFC 9116 section 3 requires. A different type invites a client to interpret the file as something else, and an unstated charset leaves any non-ASCII in it open to being decoded wrongly.",

	rule_id.SyntaxError:    "The file served at the security.txt path is not a security.txt: it holds a line that is neither a field, a comment, nor empty. Whatever is there, a tool following RFC 9116 will not read it, so the host is in practice serving nothing.",
	rule_id.MalformedField: "A field's value is not what RFC 9116 requires of that field -- a Contact, Canonical, Encryption, Acknowledgments, Policy, Hiring or CSAF field carries a URI, an Expires carries an RFC 3339 timestamp, and Preferred-Languages carries language tags. A value that is not one of those is skipped by a conforming reader, so whatever it was meant to say goes unsaid.",

	rule_id.MissingContact:    "The security.txt has no Contact field. RFC 9116 section 2.5.3 requires one, and it is the only field the file exists for: without it, the file says everything except where to send the report.",
	rule_id.MissingExpires:    "The security.txt has no Expires field. RFC 9116 section 2.5.5 requires one. Without it, a reader has no way to tell whether what the file says is still true, and stale contact details are worse than none: a report sent to an address nobody reads is a report nobody acts on.",
	rule_id.Expired:           "The security.txt has expired. RFC 9116 section 2.5.5 has a reader disregard a file whose Expires has passed, so the host is in the same position as one serving no security.txt at all -- while appearing, to anyone glancing at it, to have the matter in hand.",
	rule_id.ExpiresTooDistant: "The security.txt expires more than a year from now. RFC 9116 section 2.5.5 recommends less than that, so the file is revisited often enough that the addresses in it are still ones somebody reads.",

	rule_id.MultipleExpires:            "The security.txt has more than one Expires field, which RFC 9116 section 2.5.5 forbids. Which one a reader honours is left undecided, so the file may be treated as valid by one tool and expired by another.",
	rule_id.MultiplePreferredLanguages: "The security.txt has more than one Preferred-Languages field, which RFC 9116 section 2.5.8 forbids. The field is a single list, and repeating it leaves which one applies undecided.",

	rule_id.CanonicalMismatch: "The security.txt lists Canonical URIs, and the URI it was retrieved from is not among them. RFC 9116 section 2.5.2 says that in this case the contents SHOULD NOT be trusted: the field exists so that a copy of the file found somewhere else can be told from the genuine one, and a mismatch is what a copy planted elsewhere would look like.",

	rule_id.CheckNotDetermined: "The check could not be completed, so nothing is reported about it either way. The properties of this result name the check and say what stopped it. It is not a pass.",
}
