package content_security_policy

import (
	"fmt"
	"net"
	"slices"
	"strings"

	"github.com/altshiftab/altshift_web_security/pkg/http/header_analysis/analysis/content_security_policy/allowlist_bypass"
	httpHeadersSecurityCheckerInternal "github.com/altshiftab/altshift_web_security/pkg/http/header_analysis/analysis/internal"
	"github.com/altshiftab/altshift_web_security/pkg/http/header_analysis/rule_id"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	contentSecurityPolicyTypes "github.com/altshiftab/utils_go/pkg/http/types/content_security_policy"
	"github.com/altshiftab/utils_go/pkg/net/publicsuffix"
	"github.com/altshiftab/utils_go/pkg/sarif"
)

// sharedHosts serve what anyone publishes, telling it apart by path, as npm's CDNs and the path-style endpoints of
// cloud storage do; a subdomain of one, where it has any, is one publisher's.
var sharedHosts = []string{
	"cdn.jsdelivr.net",
	"fastly.jsdelivr.net",
	"gcore.jsdelivr.net",
	"unpkg.com",
	"s3.amazonaws.com",
	"storage.googleapis.com",
}

// firstPartySuffixes are private suffixes whose subdomains are their operator's own services rather than users' sites.
var firstPartySuffixes = map[string]bool{
	"googleapis.com": true,
}

// isSharedHost reports whether a host is one of sharedHosts or one of S3's regional endpoints.
func isSharedHost(host string) bool {
	if slices.Contains(sharedHosts, host) {
		return true
	}

	first, rest, _ := strings.Cut(host, ".")
	return (first == "s3" || strings.HasPrefix(first, "s3-")) && (rest == "amazonaws.com" || strings.HasSuffix(rest, ".amazonaws.com"))
}

// sharedHostOf returns the shared host a source's host reaches, if any, and whether the source is confined to one
// publisher's part of it: a subdomain or, given the host itself, a path.
func sharedHostOf(host string, rooted bool) (string, bool) {
	base, wildcard := strings.CutPrefix(host, "*.")
	if wildcard {
		if isSharedHost(base) {
			return base, false
		}
		for _, shared := range sharedHosts {
			if strings.HasSuffix(shared, "."+base) {
				return shared, false
			}
		}
	} else if isSharedHost(host) {
		return host, !rooted
	}

	for _, shared := range sharedHosts {
		if strings.HasSuffix(base, "."+shared) {
			return shared, true
		}
	}

	return "", false
}

// defaultPort reports whether a host source's port is the one its scheme is served on, or any; the lists name
// hosts on their default ports.
func defaultPort(source *contentSecurityPolicyTypes.HostSource) bool {
	switch source.PortString {
	case "", "*":
		return true
	case "443":
		return slices.Contains([]string{"", "https", "wss"}, strings.ToLower(source.Scheme))
	case "80":
		return slices.Contains([]string{"", "http", "ws"}, strings.ToLower(source.Scheme))
	default:
		return false
	}
}

// isScriptDirective reports whether a directive decides where script may be loaded from.
func isScriptDirective(directiveName string) bool {
	switch directiveName {
	case directiveDefaultSrc, directiveScriptSrc, "script-src-attr", "script-src-elem", "worker-src":
		return true
	default:
		return false
	}
}

// hostParts is a host source's host read against the Public Suffix List, a leading "*." wildcard included, which
// domain_parts refuses.
type hostParts struct {
	// host is the host in lower case, without a trailing dot.
	host string
	// platform is, for one publisher's site on a suffix from the list's private section or a wildcard spanning such a
	// suffix, the domain on which anyone can have a site of their own, as github.io; it is empty for any other host.
	platform string
	// spansRegistrable is whether a wildcard stands where the registrable label would, or above it, as in *.com.
	spansRegistrable bool
	// registeredDomain is the public suffix and the label before it, empty where the host has none.
	registeredDomain string
}

// wildcardRule reports whether the list makes every name directly under a domain a public suffix of its own.
func wildcardRule(domain string) bool {
	probe := "-." + domain
	suffix, _ := publicsuffix.PublicSuffix(probe)
	return suffix == probe
}

func parseHost(host string) *hostParts {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" || host == "*" || net.ParseIP(host) != nil {
		return nil
	}

	suffix, icann := publicsuffix.PublicSuffix(host)
	// A suffix the list does not know is a single label, the list's default rule.
	known := icann || strings.Contains(suffix, ".")
	private := !icann && known
	parts := &hostParts{host: host}

	if base, wildcard := strings.CutPrefix(host, "*."); wildcard && known && (suffix == base || suffix == host) {
		parts.spansRegistrable = true
		if private {
			parts.platform = base
		}
		return parts
	}

	switch {
	case !private || firstPartySuffixes[suffix]:
	case suffix != host:
		parts.platform = suffix
	default:
		// The platform's own host is no publisher's, but a name that is a suffix only by a wildcard rule, as an EC2
		// instance's is, is one publisher's.
		if _, parent, found := strings.Cut(host, "."); found && wildcardRule(parent) {
			parts.platform = parent
		}
	}

	if registeredDomain, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
		parts.registeredDomain = registeredDomain
	}

	return parts
}

func makeSourceResult(ruleId string, text string) *sarif.Result {
	result := httpHeadersSecurityCheckerInternal.MakeRuleIdResult(ruleId)
	result.Message = &sarif.Message{Text: text}
	return result
}

// Phrases shared by the messages of sources that let an attacker's script through.
const (
	ineffectiveSuffix = " which makes the directive ineffective against cross-site scripting (XSS)."
	platformSuffix    = " a platform the Public Suffix List lists as giving its users sites of their own"
	publicHostSuffix  = " a host serving content that anyone can publish there"
)

func makeUserContentResult(level sarif.Level, text string) *sarif.Result {
	result := makeSourceResult(rule_id.ContentSecurityPolicyUserContentScriptSource, text)
	result.Level = level
	return result
}

// hostResult is the one result a host source's host earns, if any: a wildcard spanning registered domains, or in a
// directive that decides where script comes from, the most direct way it lets an attacker's script through.
func hostResult(
	directiveName string,
	source *contentSecurityPolicyTypes.HostSource,
	evalAllowed bool,
) (*sarif.Result, error) {
	parts := parseHost(source.Host)
	if parts == nil {
		return nil, nil
	}

	sourceString := source.String()
	scriptDirective := isScriptDirective(directiveName)

	// A port other than the default reaches none of the listed hosts, though a wildcard still spans registered domains.
	listedPort := defaultPort(source)

	if parts.spansRegistrable {
		if scriptDirective && parts.platform != "" && listedPort {
			return makeUserContentResult(
				sarif.LevelError,
				fmt.Sprintf(
					"The %s source of the %s directive allows every site on %s,"+platformSuffix+". An attacker can get a site there, serve a script from it and have the page run it,"+ineffectiveSuffix,
					sourceString,
					directiveName,
					parts.platform,
				),
			), nil
		}

		hosts := "any external host with a specific effective top-level domain"
		if parts.platform != "" {
			hosts = "any site on " + parts.platform + "," + platformSuffix
		}
		result := makeSourceResult(
			rule_id.ContentSecurityPolicyWildcardRegisteredDomainHost,
			fmt.Sprintf(
				"The %s source of the %s directive effectively uses a wildcard host source. Using a wildcard in place of the registered domain of a host is unsafe as it permits content to be loaded from %s.",
				sourceString,
				directiveName,
				hosts,
			),
		)
		result.Level = getDirectiveNameUntrustedSourceLevel(directiveName)
		return result, nil
	}

	if !scriptDirective || !listedPort {
		return nil, nil
	}

	path := source.Path
	rooted := path == "" || path == "/"

	userContent, confined, err := allowlist_bypass.UserContent(parts.host, path)
	if err != nil {
		return nil, altshiftErrors.New(fmt.Errorf("allowlist bypass user content: %w", err), parts.host, path)
	}
	sharedHost, sharedConfined := sharedHostOf(parts.host, rooted)

	// A host serving anyone's content as a whole is the most direct bypass there is.
	var publicHost string
	switch {
	case userContent != nil && !confined:
		publicHost = userContent.Host
	case sharedHost != "" && !sharedConfined:
		publicHost = sharedHost
	}
	if publicHost != "" {
		return makeUserContentResult(
			sarif.LevelError,
			fmt.Sprintf(
				"The %s source of the %s directive allows %s,"+publicHostSuffix+". An attacker can publish a script there and have the page run it,"+ineffectiveSuffix,
				sourceString,
				directiveName,
				publicHost,
			),
		), nil
	}

	jsonp, err := allowlist_bypass.Jsonp(parts.host, path, evalAllowed)
	if err != nil {
		return nil, altshiftErrors.New(fmt.Errorf("allowlist bypass jsonp: %w", err), parts.host, path)
	}
	if jsonp != nil {
		text := fmt.Sprintf(
			"The %s source of the %s directive allows the JSONP endpoint %s. A JSONP endpoint answers with script calling a function the request names, so an attacker able to add a script element can name code of their own instead and have the page run it,"+ineffectiveSuffix,
			sourceString,
			directiveName,
			jsonp,
		)
		if jsonp.NeedsEval {
			text += " This endpoint runs that code through eval, which the directive permits with 'unsafe-eval'."
		}
		return makeSourceResult(rule_id.ContentSecurityPolicyJsonpScriptSource, text), nil
	}

	gadget, err := allowlist_bypass.ScriptGadget(parts.host, path)
	if err != nil {
		return nil, altshiftErrors.New(fmt.Errorf("allowlist bypass script gadget: %w", err), parts.host, path)
	}
	if gadget != nil {
		return makeSourceResult(
			rule_id.ContentSecurityPolicyScriptGadgetSource,
			fmt.Sprintf(
				"The %s source of the %s directive allows %s, which serves %s, a library that acts as a script gadget. A script gadget turns markup into code, as AngularJS does with an expression in a template, so an attacker able to inject HTML can load the library from the allowed host and have it run code of their own,"+ineffectiveSuffix,
				sourceString,
				directiveName,
				gadget,
				gadget.Library,
			),
		), nil
	}

	// One publisher's part of such a host is only as trustworthy as whoever holds it.
	var partOf, partOfSuffix string
	switch {
	case userContent != nil:
		partOf, partOfSuffix = userContent.Host, publicHostSuffix
	case sharedHost != "":
		partOf, partOfSuffix = sharedHost, publicHostSuffix
	case parts.platform != "":
		partOf, partOfSuffix = parts.platform, platformSuffix
	}
	if partOf != "" {
		return makeUserContentResult(
			sarif.LevelWarning,
			fmt.Sprintf(
				"The %s source of the %s directive allows part of %s,"+partOfSuffix+". The page runs whatever script whoever holds that part publishes there: an attacker, where the part is not this site's own or once its name lapses and someone else takes it.",
				sourceString,
				directiveName,
				partOf,
			),
		), nil
	}

	var cdnDomain string
	if cdnFullDomainsSet[parts.host] {
		cdnDomain = parts.host
	} else if cdnRegisteredDomainsSet[parts.registeredDomain] {
		cdnDomain = parts.registeredDomain
	}
	if cdnDomain != "" {
		return makeSourceResult(
			rule_id.ContentSecurityPolicyCdnScriptSource,
			fmt.Sprintf(
				"The %s directive, which controls code execution, uses a content-delivery network (CDN) host source with the domain %s. Permitting code to be loaded and executed from CDNs effectively renders a directive ineffective as CDNs are hosting user-provided content, which an attacker could arrange to be malicious to achieve cross-site scripting (XSS) etc.",
				directiveName,
				cdnDomain,
			),
		), nil
	}

	return nil, nil
}
