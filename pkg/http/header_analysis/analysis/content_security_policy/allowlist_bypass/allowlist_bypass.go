// Package allowlist_bypass knows the places on the web that defeat a script allowlist: JSONP endpoints, copies of
// libraries that act as script gadgets, and hosts serving whatever anyone publishes. A Content-Security-Policy that
// allows any of them allows an attacker's script along with them.
//
// The lists are vendored from Google's CSP Evaluator and from csp-toolkit; data/NOTICE says what came from where.
package allowlist_bypass

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"

	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
)

//go:embed data/csp_evaluator_jsonp.txt
var cspEvaluatorJsonp string

//go:embed data/csp_evaluator_jsonp_needs_eval.txt
var cspEvaluatorJsonpNeedsEval string

//go:embed data/csp_evaluator_angular.txt
var cspEvaluatorAngular string

//go:embed data/csp_toolkit_cdn_gadgets.json
var cspToolkitCdnGadgets []byte

//go:embed data/csp_toolkit_arbitrary_hosting.txt
var cspToolkitArbitraryHosting string

// anyLibrary is what csp-toolkit's gadget list names where a host serves anything anyone publishes, which makes it a
// user-content host rather than a gadget.
const anyLibrary = "any"

// angularLibrary names the library of CSP Evaluator's gadget list, in csp-toolkit's spelling.
const angularLibrary = "angularjs"

// markupGadgetLibraries are the libraries of csp-toolkit's gadget list that turn markup into code; the rest of them do
// so only when the page's own code hands them the attacker's input.
var markupGadgetLibraries = map[string]bool{
	angularLibrary: true,
	"dojo":         true,
	"knockout":     true,
	"vue":          true,
}

// Listing is one known bypass: where it is, and for a gadget, what it is.
type Listing struct {
	// Host is the host the bypass is on, in lower case.
	Host string
	// Path is where on the host it is, possibly with "*" standing for any run of characters within a segment; empty
	// where the listing is for the whole host.
	Path string
	// Library names the library of a script gadget, and is empty for any other listing.
	Library string
	// NeedsEval is whether a JSONP endpoint runs its payload through eval, so that only 'unsafe-eval' lets it work.
	NeedsEval bool
}

func (listing *Listing) String() string {
	if listing == nil {
		return ""
	}

	return listing.Host + listing.Path
}

type lists struct {
	jsonp       []*Listing
	gadgets     []*Listing
	userContent []*Listing
}

type cdnGadget struct {
	Library        string `json:"library"`
	VulnerablePath string `json:"vulnerable_path,omitzero"`
}

// parseLines returns the entries of a vendored list, one to a line, without its comments.
func parseLines(data string) []string {
	var entries []string
	for line := range strings.Lines(data) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		entries = append(entries, line)
	}

	return entries
}

// parseUrl splits a scheme-relative URL of CSP Evaluator's lists into a listing, dropping a query, which a source
// cannot restrict.
func parseUrl(url string, library string) *Listing {
	rest := strings.TrimPrefix(url, "//")
	rest, _, _ = strings.Cut(rest, "?")
	host, path, found := strings.Cut(rest, "/")
	if found {
		path = "/" + path
	}

	return &Listing{Host: strings.ToLower(host), Path: path, Library: library}
}

// appendUnique appends a listing unless one for the same place and library is already there.
func appendUnique(listings []*Listing, listing *Listing) []*Listing {
	for _, existing := range listings {
		if *existing == *listing {
			return listings
		}
	}

	return append(listings, listing)
}

// appendHost appends a listing unless one for the same host is already there.
func appendHost(listings []*Listing, listing *Listing) []*Listing {
	for _, existing := range listings {
		if existing.Host == listing.Host {
			return listings
		}
	}

	return append(listings, listing)
}

func load() (*lists, error) {
	loaded := &lists{}

	needsEval := map[string]struct{}{}
	for _, host := range parseLines(cspEvaluatorJsonpNeedsEval) {
		needsEval[strings.ToLower(host)] = struct{}{}
	}
	for _, url := range parseLines(cspEvaluatorJsonp) {
		listing := parseUrl(url, "")
		_, listing.NeedsEval = needsEval[listing.Host]
		loaded.jsonp = appendUnique(loaded.jsonp, listing)
	}
	for _, url := range parseLines(cspEvaluatorAngular) {
		loaded.gadgets = appendUnique(loaded.gadgets, parseUrl(url, angularLibrary))
	}
	for _, host := range parseLines(cspToolkitArbitraryHosting) {
		loaded.userContent = appendHost(loaded.userContent, &Listing{Host: strings.ToLower(host)})
	}

	var gadgetsByHost map[string][]*cdnGadget
	if err := json.Unmarshal(cspToolkitCdnGadgets, &gadgetsByHost); err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("json unmarshal (csp-toolkit cdn gadgets): %w", err))
	}
	for _, host := range slices.Sorted(maps.Keys(gadgetsByHost)) {
		for _, gadget := range gadgetsByHost[host] {
			if gadget == nil {
				continue
			}

			listedHost := strings.ToLower(host)
			path, _, _ := strings.Cut(gadget.VulnerablePath, "?")
			switch {
			case gadget.Library == anyLibrary:
				loaded.userContent = appendHost(loaded.userContent, &Listing{Host: listedHost, Path: path})
			case markupGadgetLibraries[gadget.Library]:
				loaded.gadgets = appendUnique(loaded.gadgets, &Listing{Host: listedHost, Path: path, Library: gadget.Library})
			}
		}
	}

	return loaded, nil
}

var loadLists = sync.OnceValues(load)

// normalizeHost puts a source's host in the form the lists are in.
func normalizeHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(host), ".")
}

// hostAllows reports whether a source's host, possibly a "*." wildcard, matches a listed host.
func hostAllows(sourceHost string, listedHost string) bool {
	if base, wildcard := strings.CutPrefix(sourceHost, "*."); wildcard {
		return strings.HasSuffix(listedHost, "."+base)
	}

	return sourceHost == listedHost
}

// segmentMatches reports whether a path segment matches a listed one, in which "*" stands for any run of characters.
func segmentMatches(pattern string, segment string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == segment
	}

	first, last := parts[0], parts[len(parts)-1]
	if !strings.HasPrefix(segment, first) {
		return false
	}
	segment = segment[len(first):]

	for _, part := range parts[1 : len(parts)-1] {
		index := strings.Index(segment, part)
		if index < 0 {
			return false
		}
		segment = segment[index+len(part):]
	}

	return strings.HasSuffix(segment, last)
}

// pathAllows reports whether a source's path allows a listed path, as CSP matches paths and CSP Evaluator matches its
// lists: a path ending in "/" allows what is beneath it, any other path only itself, and a source with no path
// allows the whole host. A listing for the whole host is allowed only by a source with no path, the list not saying
// where on the host the bypass is.
func pathAllows(sourcePath string, listedPath string) bool {
	if sourcePath == "" || sourcePath == "/" {
		return true
	}
	if listedPath == "" || listedPath == "/" {
		return false
	}

	sourceSegments := strings.Split(strings.TrimPrefix(sourcePath, "/"), "/")
	listedSegments := strings.Split(strings.TrimPrefix(listedPath, "/"), "/")

	if strings.HasSuffix(sourcePath, "/") {
		sourceSegments = sourceSegments[:len(sourceSegments)-1]
		if len(sourceSegments) >= len(listedSegments) {
			return false
		}
	} else if len(sourceSegments) != len(listedSegments) {
		return false
	}

	for index, segment := range sourceSegments {
		if !segmentMatches(listedSegments[index], segment) {
			return false
		}
	}

	return true
}

// Jsonp returns a JSONP endpoint that a host source with the given host and path allows, or nil where it allows none
// known. evalAllowed says whether the directive allows 'unsafe-eval', without which some endpoints do not work.
func Jsonp(host string, path string, evalAllowed bool) (*Listing, error) {
	loaded, err := loadLists()
	if err != nil {
		return nil, err
	}

	host = normalizeHost(host)
	for _, listing := range loaded.jsonp {
		if !hostAllows(host, listing.Host) || !pathAllows(path, listing.Path) {
			continue
		}
		if listing.NeedsEval && !evalAllowed {
			continue
		}

		return listing, nil
	}

	return nil, nil
}

// ScriptGadget returns a copy of a script-gadget library that a host source with the given host and path allows, or
// nil where it allows none known.
func ScriptGadget(host string, path string) (*Listing, error) {
	loaded, err := loadLists()
	if err != nil {
		return nil, err
	}

	host = normalizeHost(host)
	for _, listing := range loaded.gadgets {
		if hostAllows(host, listing.Host) && pathAllows(path, listing.Path) {
			return listing, nil
		}
	}

	return nil, nil
}

// UserContent returns a host serving whatever anyone publishes that a host source with the given host and path
// allows, or nil where it allows none known, and whether the source is confined to part of it -- a subdomain, or a
// path short of where the listing says anyone publishes -- which may be one publisher's.
func UserContent(host string, path string) (*Listing, bool, error) {
	loaded, err := loadLists()
	if err != nil {
		return nil, false, err
	}

	host = normalizeHost(host)
	base, _ := strings.CutPrefix(host, "*.")

	for _, candidate := range loaded.userContent {
		switch {
		case hostAllows(host, candidate.Host):
			return candidate, !pathAllows(path, candidate.Path), nil
		case strings.HasSuffix(base, "."+candidate.Host):
			return candidate, true, nil
		}
	}

	return nil, false, nil
}
