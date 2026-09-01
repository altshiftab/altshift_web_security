package rule_id

const (
	// Missing is a host that serves no security.txt at all.
	Missing = "security_txt_missing"
	// NotAtWellKnownPath is one served only at the legacy top-level path.
	NotAtWellKnownPath = "security_txt_not_at_well_known_path"
	// NotHttps is one that ended up being served over an unencrypted channel.
	NotHttps = "security_txt_not_https"
	// BadContentType is one not served as text/plain; charset=utf-8.
	BadContentType = "security_txt_bad_content_type"

	// SyntaxError is a file that is not a security.txt.
	SyntaxError = "security_txt_syntax_error"
	// MalformedField is a field whose value is not what its name requires.
	MalformedField = "security_txt_malformed_field"

	// MissingContact is a file that names nobody to report to, which RFC 9116
	// requires and without which the file achieves nothing.
	MissingContact = "security_txt_missing_contact"
	// MissingExpires is a file that never goes stale, which RFC 9116 also requires.
	MissingExpires = "security_txt_missing_expires"
	// Expired is a file whose Expires has passed, which a reporter is to disregard.
	Expired = "security_txt_expired"
	// ExpiresTooDistant is one whose Expires is more than the recommended year out.
	ExpiresTooDistant = "security_txt_expires_too_distant"

	// MultipleExpires and MultiplePreferredLanguages are fields RFC 9116 allows
	// only once.
	MultipleExpires            = "security_txt_multiple_expires"
	MultiplePreferredLanguages = "security_txt_multiple_preferred_languages"

	// CanonicalMismatch is a file whose Canonical fields do not name where it was
	// found, which RFC 9116 says makes it untrustworthy.
	CanonicalMismatch = "security_txt_canonical_mismatch"

	// CheckNotDetermined stands for a check that could not be run, carrying the
	// check and the reason in its properties.
	CheckNotDetermined = "security_txt_check_not_determined"
)
