package allowlist_bypass

import (
	"testing"
)

// The vendored lists load, and hold what they are known to; a refresh that lost one would leave it empty.
func TestListsLoad(t *testing.T) {
	t.Parallel()

	loaded, err := loadLists()
	if err != nil {
		t.Fatalf("loadLists err = %v", err)
	}

	testCases := []struct {
		name     string
		listings []*Listing
		minimum  int
		want     Listing
	}{
		{name: "jsonp", listings: loaded.jsonp, minimum: 100, want: Listing{Host: "accounts.google.com", Path: "/o/oauth2/revoke"}},
		{name: "jsonp needing eval", listings: loaded.jsonp, minimum: 100, want: Listing{Host: "www.googletagmanager.com", Path: "/gtm/js", NeedsEval: true}},
		{name: "jsonp for a whole host", listings: loaded.jsonp, minimum: 100, want: Listing{Host: "cdn.jsdelivr.net"}},
		{name: "angular gadgets", listings: loaded.gadgets, minimum: 41, want: Listing{Host: "ajax.googleapis.com", Path: "/ajax/libs/angularjs/1.2.0rc1/angular-route.min.js", Library: angularLibrary}},
		{name: "cdn gadgets", listings: loaded.gadgets, minimum: 41, want: Listing{Host: "unpkg.com", Path: "/vue@2.*/dist/vue.js", Library: "vue"}},
		{name: "cdn gadget for a whole host", listings: loaded.gadgets, minimum: 41, want: Listing{Host: "stackpath.bootstrapcdn.com", Library: angularLibrary}},
		{name: "arbitrary hosting", listings: loaded.userContent, minimum: 18, want: Listing{Host: "pastebin.com"}},
		{name: "a gadget host serving anything", listings: loaded.userContent, minimum: 18, want: Listing{Host: "cdn.statically.io", Path: "/gh/*"}},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if len(testCase.listings) < testCase.minimum {
				t.Errorf("%s: %d listings, want at least %d", testCase.name, len(testCase.listings), testCase.minimum)
			}

			for _, listing := range testCase.listings {
				if *listing == testCase.want {
					return
				}
			}
			t.Errorf("%s: no listing %+v", testCase.name, testCase.want)
		})
	}
}

// A listing found in two lists is kept once, and a user-content host once whatever its paths.
func TestListsHoldNoDuplicates(t *testing.T) {
	t.Parallel()

	loaded, err := loadLists()
	if err != nil {
		t.Fatalf("loadLists err = %v", err)
	}

	testCases := []struct {
		name     string
		listings []*Listing
		key      func(*Listing) Listing
	}{
		{name: "jsonp", listings: loaded.jsonp, key: func(listing *Listing) Listing { return *listing }},
		{name: "gadgets", listings: loaded.gadgets, key: func(listing *Listing) Listing { return *listing }},
		// cdn.rawgit.com is in both of csp-toolkit's lists, with a path in one of them.
		{name: "user content", listings: loaded.userContent, key: func(listing *Listing) Listing { return Listing{Host: listing.Host} }},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			seen := map[Listing]bool{}
			for _, listing := range testCase.listings {
				key := testCase.key(listing)
				if seen[key] {
					t.Errorf("%s: %+v is listed twice", testCase.name, key)
				}
				seen[key] = true
			}
		})
	}
}

// Of csp-toolkit's gadgets, only the libraries that turn markup into code are kept.
func TestGadgetsAreMarkupDriven(t *testing.T) {
	t.Parallel()

	loaded, err := loadLists()
	if err != nil {
		t.Fatalf("loadLists err = %v", err)
	}

	for _, listing := range loaded.gadgets {
		if !markupGadgetLibraries[listing.Library] {
			t.Errorf("%s: library %q does not turn markup into code", listing, listing.Library)
		}
	}
}

func TestSegmentMatches(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		pattern string
		segment string
		want    bool
	}{
		{name: "literal", pattern: "angular.js", segment: "angular.js", want: true},
		{name: "literal mismatch", pattern: "angular.js", segment: "jquery", want: false},
		{name: "trailing star", pattern: "1.*", segment: "1.8.2", want: true},
		{name: "trailing star mismatch", pattern: "1.*", segment: "2.0.0", want: false},
		{name: "inner star", pattern: "jquery-*.min.js", segment: "jquery-3.7.1.min.js", want: true},
		{name: "inner star mismatch", pattern: "jquery-*.min.js", segment: "jquery-3.7.1.js", want: false},
		{name: "star alone", pattern: "*", segment: "anything", want: true},
		{name: "star matching nothing", pattern: "angular@*", segment: "angular@", want: true},
		{name: "prefix and suffix may not overlap", pattern: "ab*ba", segment: "aba", want: false},
		{name: "two stars", pattern: "a*b*c", segment: "aXbYc", want: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := segmentMatches(testCase.pattern, testCase.segment); got != testCase.want {
				t.Errorf("%s: segmentMatches(%q, %q) = %v, want %v", testCase.name, testCase.pattern, testCase.segment, got, testCase.want)
			}
		})
	}
}

func TestPathAllows(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		sourcePath string
		listedPath string
		want       bool
	}{
		{name: "no path allows a listed path", sourcePath: "", listedPath: "/a/b.js", want: true},
		{name: "the root allows a listed path", sourcePath: "/", listedPath: "/a/b.js", want: true},
		{name: "no path allows a whole-host listing", sourcePath: "", listedPath: "", want: true},
		{name: "a path does not allow a whole-host listing", sourcePath: "/a/", listedPath: "", want: false},
		{name: "a path does not allow a listing at the root", sourcePath: "/a/", listedPath: "/", want: false},
		{name: "a directory allows what is beneath it", sourcePath: "/a/", listedPath: "/a/b/c.js", want: true},
		{name: "a directory does not allow a sibling", sourcePath: "/x/", listedPath: "/a/b.js", want: false},
		{name: "a directory does not allow a file of its name", sourcePath: "/a/b.js/", listedPath: "/a/b.js", want: false},
		{name: "a directory allows a listed directory", sourcePath: "/counter/gpp/", listedPath: "/counter/gpp/", want: true},
		{name: "a file allows itself", sourcePath: "/a/b.js", listedPath: "/a/b.js", want: true},
		{name: "a file does not allow what is beside it", sourcePath: "/a/c.js", listedPath: "/a/b.js", want: false},
		{name: "a file is not a prefix", sourcePath: "/a/b", listedPath: "/a/b.js", want: false},
		{name: "a file does not allow a directory of its name", sourcePath: "/counter/gpp", listedPath: "/counter/gpp/", want: false},
		{name: "a directory a pattern reaches", sourcePath: "/ajax/libs/angular.js/1.8.2/", listedPath: "/ajax/libs/angular.js/1.*/angular.min.js", want: true},
		{name: "a directory a pattern does not reach", sourcePath: "/ajax/libs/angular.js/2.0.0/", listedPath: "/ajax/libs/angular.js/1.*/angular.min.js", want: false},
		{name: "a file a pattern matches", sourcePath: "/jquery-3.7.1.min.js", listedPath: "/jquery-*.min.js", want: true},
		{name: "a star does not cross a slash", sourcePath: "/jquery-3/7.min.js", listedPath: "/jquery-*.min.js", want: false},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := pathAllows(testCase.sourcePath, testCase.listedPath); got != testCase.want {
				t.Errorf("%s: pathAllows(%q, %q) = %v, want %v", testCase.name, testCase.sourcePath, testCase.listedPath, got, testCase.want)
			}
		})
	}
}

func TestHostAllows(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		sourceHost string
		listedHost string
		want       bool
	}{
		{name: "the same host", sourceHost: "www.google.com", listedHost: "www.google.com", want: true},
		{name: "another host", sourceHost: "mail.google.com", listedHost: "www.google.com", want: false},
		{name: "a wildcard over it", sourceHost: "*.google.com", listedHost: "www.google.com", want: true},
		{name: "a wildcard over its parent", sourceHost: "*.com", listedHost: "www.google.com", want: true},
		{name: "a wildcard does not cover its own base", sourceHost: "*.google.com", listedHost: "google.com", want: false},
		{name: "a wildcard does not cover a lookalike", sourceHost: "*.google.com", listedHost: "www.notgoogle.com", want: false},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := hostAllows(testCase.sourceHost, testCase.listedHost); got != testCase.want {
				t.Errorf("%s: hostAllows(%q, %q) = %v, want %v", testCase.name, testCase.sourceHost, testCase.listedHost, got, testCase.want)
			}
		})
	}
}

func TestJsonp(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		host        string
		path        string
		evalAllowed bool
		want        string
	}{
		{name: "a listed host", host: "accounts.google.com", want: "accounts.google.com/o/oauth2/revoke"},
		{name: "case and a trailing dot", host: "Accounts.Google.COM.", want: "accounts.google.com/o/oauth2/revoke"},
		{name: "a wildcard over listed hosts, not over the one at its base", host: "*.yandex.ru", want: "mc.yandex.ru/watch/24306916/1"},
		{name: "a path away from it", host: "www.google.com", path: "/recaptcha/"},
		{name: "a host needing eval, without it", host: "www.googletagmanager.com"},
		{name: "a host needing eval, with it", host: "www.googletagmanager.com", evalAllowed: true, want: "www.googletagmanager.com/gtm/js"},
		{name: "an unlisted host", host: "example.com"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			listing, err := Jsonp(testCase.host, testCase.path, testCase.evalAllowed)
			if err != nil {
				t.Fatalf("%s: Jsonp err = %v", testCase.name, err)
			}
			if got := listing.String(); got != testCase.want {
				t.Errorf("%s: Jsonp(%q, %q) = %q, want %q", testCase.name, testCase.host, testCase.path, got, testCase.want)
			}
		})
	}
}

func TestScriptGadget(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		host        string
		path        string
		wantListing string
		wantLibrary string
	}{
		{name: "a listed host", host: "cdnjs.cloudflare.com", wantListing: "cdnjs.cloudflare.com/ajax/libs/angular.js/1.2.16/angular.min.js", wantLibrary: angularLibrary},
		{name: "a version a pattern matches", host: "cdnjs.cloudflare.com", path: "/ajax/libs/knockout/3.5.1/knockout-min.js", wantListing: "cdnjs.cloudflare.com/ajax/libs/knockout/*/knockout-min.js", wantLibrary: "knockout"},
		{name: "a library that is no gadget", host: "cdnjs.cloudflare.com", path: "/ajax/libs/jquery/"},
		{name: "a library that needs the page's code to be one", host: "code.jquery.com"},
		{name: "a whole-host listing from the root", host: "stackpath.bootstrapcdn.com", wantListing: "stackpath.bootstrapcdn.com", wantLibrary: angularLibrary},
		{name: "a whole-host listing from a path", host: "stackpath.bootstrapcdn.com", path: "/bootstrap/"},
		{name: "an unlisted host", host: "example.com"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			listing, err := ScriptGadget(testCase.host, testCase.path)
			if err != nil {
				t.Fatalf("%s: ScriptGadget err = %v", testCase.name, err)
			}

			var library string
			if listing != nil {
				library = listing.Library
			}
			if got := listing.String(); got != testCase.wantListing || library != testCase.wantLibrary {
				t.Errorf("%s: ScriptGadget(%q, %q) = %q (%q), want %q (%q)", testCase.name, testCase.host, testCase.path, got, library, testCase.wantListing, testCase.wantLibrary)
			}
		})
	}
}

func TestUserContent(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name         string
		host         string
		path         string
		want         string
		wantConfined bool
	}{
		{name: "a listed host", host: "raw.githubusercontent.com", want: "raw.githubusercontent.com"},
		{name: "a listed host from the root", host: "raw.githubusercontent.com", path: "/", want: "raw.githubusercontent.com"},
		{name: "a path on a listed host", host: "raw.githubusercontent.com", path: "/example/repository/", want: "raw.githubusercontent.com", wantConfined: true},
		{name: "a subdomain of a listed host", host: "example.surge.sh", want: "surge.sh", wantConfined: true},
		{name: "a wildcard over a listed host", host: "*.githubusercontent.com", want: "raw.githubusercontent.com"},
		{name: "a wildcard does not cover the listed host at its base", host: "*.pastebin.com"},
		{name: "a path where the listing says anyone publishes", host: "cdn.statically.io", path: "/gh/", want: "cdn.statically.io"},
		{name: "a path within one publisher's part", host: "cdn.statically.io", path: "/gh/example/", want: "cdn.statically.io", wantConfined: true},
		{name: "a wildcard under a listed host", host: "*.example.surge.sh", want: "surge.sh", wantConfined: true},
		{name: "a host from csp-toolkit's gadget list serving anything", host: "cdn.statically.io", want: "cdn.statically.io"},
		{name: "an unlisted host", host: "example.com"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			listing, confined, err := UserContent(testCase.host, testCase.path)
			if err != nil {
				t.Fatalf("%s: UserContent err = %v", testCase.name, err)
			}

			var host string
			if listing != nil {
				host = listing.Host
			}
			if host != testCase.want || confined != testCase.wantConfined {
				t.Errorf("%s: UserContent(%q, %q) = %q, %v, want %q, %v", testCase.name, testCase.host, testCase.path, host, confined, testCase.want, testCase.wantConfined)
			}
		})
	}
}
