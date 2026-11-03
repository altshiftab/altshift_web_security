# altshift_web_security

How a site is exposed to whoever visits it.

The web-layer counterpart to `altshift_domain_security`, which asks the same kind of question of a
domain's mail. It shares that repository's shape: a rule id per thing that can be wrong, a curated
severity and description behind each, and findings emitted as SARIF, so a run is something another
tool can read rather than only a person.

Packages are grouped by the layer they probe -- `pkg/http` today, `pkg/tls` when the TLS a site
negotiates is asked about too -- so where a new check belongs is never a judgment call.

## Packages

| Package | What it answers |
| --- | --- |
| `pkg/http/header_analysis/analysis` | What is wrong with the security headers this response serves? |
| `pkg/http/header_analysis/analysis/content_security_policy` | Unsafe keywords, wildcard and loopback sources, script sources an attacker can use, the directives a policy leaves out |
| `pkg/http/header_analysis/analysis/content_security_policy/allowlist_bypass` | The JSONP endpoints, script gadgets and user-content hosts that defeat a script allowlist |
| `pkg/http/header_analysis/analysis/strict_transport_security` | A missing or short max-age, no includeSubDomains, no preload |
| `pkg/http/header_analysis/analysis/x_frame_options` | Obsolete, and values that frame anyway |
| `pkg/http/header_analysis/analysis/x_content_type_options` | Anything that is not `nosniff` |
| `pkg/http/header_analysis/analysis/referrer_policy` | A policy that sends the URL across origins |
| `pkg/http/header_analysis/analysis/cross_origin_opener_policy` | Missing, `unsafe-none`, and values browsers do not take |
| `pkg/http/header_analysis/analysis/cross_origin_embedder_policy` | The same, for what a document may embed |
| `pkg/http/header_analysis/analysis/cross_origin_resource_policy` | The same, for who may load a resource |
| `pkg/http/header_analysis/header_block` | The headers of a response captured elsewhere, as pasted or piped |
| `pkg/http/header_analysis/rule_id` | The id of every rule that can be raised |
| `pkg/http/header_analysis/rule_id_mappings` | What each rule is called, what it means, and how much it is worth |
| `pkg/tls/wire` | A ClientHello as bytes, and a server's answer read back out of them |
| `pkg/tls/cipher_suite` | The IANA registry, and what the policy makes of each entry |
| `pkg/tls/probe` | What a server will negotiate, asked one aborted handshake at a time |
| `pkg/tls/observation` | What a probe saw, as data with no opinion about it |
| `pkg/tls/connection_analysis/analysis` | What is wrong with what it saw |
| `pkg/http/security_txt_analysis/retrieval` | The security.txt a host serves, and how it served it |
| `pkg/http/security_txt_analysis/analysis` | What is wrong with it, against RFC 9116 |

`analysis.AnalyzeHeaders(http.Header)` is the whole entry point. It walks the headers a response
either serves or leaves out, and returns a `*sarif.Run` holding a finding for each thing wrong and a
rule table describing them.

Headers with a package of their own are analysed there. The rest are decided in `analysis.go`
itself, having nothing to decide: `X-XSS-Protection` and `Feature-Policy` are obsolete, `Expect-CT`
and `Public-Key-Pins` deprecated, and `Server`, `X-Powered-By`, `X-AspNet-Version` and
`X-AspNetMvc-Version` say more about the system than a visitor needs to know.

Two behaviours are worth knowing before reading a run:

- A header served more than once collapses into a single `multiple_header_values` finding, at the
  worst level any one of the values would have raised on its own.
- The headers that protect a document -- CSP, COOP, COEP, Permissions-Policy -- are reported at
  level `none` when the response carries no document to protect, which a bare redirect, a 204 and a
  304 do not.

### Script sources

A host a policy takes script from is judged by what an attacker could make it serve, and earns at
most one of four rules, the most direct first:

| Rule | Severity | Raised for |
| --- | --- | --- |
| `content_security_policy_user_content_script_source` | high; medium for one publisher's part | A host anyone can publish on: a wildcard over a suffix in the Public Suffix List's private section (`*.github.io`, `*.cloudfront.net`), the arbitrary-hosting hosts csp-toolkit lists (`raw.githubusercontent.com`, `pastebin.com`), npm's CDNs (`cdn.jsdelivr.net`, `unpkg.com`) and the path-style endpoints of cloud storage (`s3.amazonaws.com`, `storage.googleapis.com`). A source confined to one site, path or package on such a host (`example.netlify.app`, `cdn.jsdelivr.net/npm/bootstrap@5.3.0/`) is medium: it is as trustworthy as whoever holds that part. |
| `content_security_policy_jsonp_script_source` | high | A JSONP endpoint on CSP Evaluator's list. The endpoints that run their payload through `eval` count only where the policy allows `'unsafe-eval'`, which `script-src` decides, falling back to `default-src`. |
| `content_security_policy_script_gadget_source` | high | A copy of a library that turns injected markup into code -- AngularJS, Dojo, Knockout or Vue -- on CSP Evaluator's or csp-toolkit's list. |
| `content_security_policy_cdn_script_source` | high | What the earlier CDN list has left to say: a host of `cdnjs.cloudflare.com`, `gstatic.com`, `jsdelivr.net` or `unpkg.com` that no other rule explains. |

A source with a path reaches only what CSP lets it reach, as CSP Evaluator matches its lists: a path
ending in `/` allows what is beneath it and any other path only itself, so
`https://www.google.com/recaptcha/` does not allow the JSONP endpoint at
`/tools/feedback/escalation-options`. A port other than the scheme's default reaches none of the
listed hosts. A platform's own host (`github.io`) is no publisher's, and the hosts under
`googleapis.com` are Google's services rather than its users' sites, though the list has it as a
private suffix.

The rules are raised in the directives that decide where script comes from -- `default-src`,
`script-src`, `script-src-elem`, `script-src-attr` and `worker-src` -- and nowhere else. A wildcard
spanning registered domains, as `*.com` and `*.co.uk` do, is
`content_security_policy_wildcard_registered_domain_host` in any directive, except that one over a
private suffix in those directives is the user-content rule instead.

The lists are vendored in `content_security_policy/allowlist_bypass/data`: the JSONP and AngularJS
lists from Google's [CSP Evaluator](https://github.com/google/csp-evaluator) (Apache-2.0), and the
gadget and arbitrary-hosting lists from [csp-toolkit](https://github.com/sampsonc/csp_toolkit) (MIT).
Its `NOTICE` names the commit each came from, and `refresh.sh` fetches them again.
[CSPBypass](https://github.com/renniepak/CSPBypass) is GPL-3.0 and is not vendored; what the rules
make of it is measured against a copy of its `data.tsv` kept elsewhere:

```
CSPBYPASS_DATA=path/to/data.tsv go test ./pkg/http/header_analysis/analysis/content_security_policy -run CspBypassCoverage -v
```

## Command

```
go install github.com/altshiftab/altshift_web_security/cmd/altshift_web_security@latest
```

```
altshift_web_security headers [-h] [-j] [-l {none,note,warning,error}] [-e]
                              [-X STRING] [-H STRING...] [-k] [-t INT]
                              [--no-follow] [URL]
```

A URL is fetched and its response analysed:

```
$ altshift_web_security headers -l error example.com
error     Content-Security-Policy  (missing_content_security_policy)
          The Content-Security-Policy header specifies various directives that control how
          external resources may be loaded and by what means interaction with external hosts
          may occur. ...
```

Without a URL, a raw header block is read from standard input, which is how a response captured
somewhere else is analysed without going back to the server. A status line may be left on the front
of it, so what `curl -D -` or a proxy log holds can be pasted whole:

```
curl -sD - -o /dev/null https://example.com | altshift_web_security headers
```

A capture of several responses, as `curl -L` leaves through a redirect, is read for the last of them,
which is the one finally served. `header_block.Parse` is the same reading, for a caller with a paste
of its own.

`--json` writes the SARIF log instead of a report: the rule table, and the header name and value
behind every finding. `--min-level` applies to both, and prunes the rule table along with the
results so the log stays internally consistent. `--exit-code` turns the pair into a gate, leaving
through status 1 when anything survives the filter:

```
altshift_web_security headers --min-level error --exit-code https://example.com
```

Requests are made with the transport's own compression turned off, because it strips
`Content-Encoding` and `Content-Length` from what it hands back once it has decompressed, and those
are two of the three fields that decide whether a response is treated as carrying a document at all.
A caller who wants to see a compressed response asks for one with `-H`.

### TLS

```
altshift_web_security tls [-j] [-l {none,note,warning,error}] [-e] [--sni NAME]
                          [-t SECS] [--connections N] [--concurrency N] HOST[:PORT]
```

```
$ altshift_web_security tls --min-level warning cloudflare.com
error     The server negotiates cipher suites that are no longer acceptable  (tls_cipher_suite_insufficient)
          The server negotiates 11 cipher suite(s) the policy considers insufficient: ...

warning   The server offers 0-RTT early data  (tls_zero_rtt_enabled)
          The server offers 0-RTT early data, accepting up to 14336 bytes in the first
          flight. ...
```

Eleven checks, matching the TLS section of an internet.nl report: the versions a server accepts, the
cipher suites it will negotiate and whether its own preference orders them sensibly, the group and
signing hash behind its key exchange, record compression, secure and client-initiated renegotiation,
0-RTT, OCSP stapling, and the extended master secret.

The classification is NCSC-NL's *IT Security Guidelines for Transport Layer Security*, 2025-05
edition, in the form internet.nl applies it: the good, sufficient and phase-out cipher lists are
theirs verbatim, and anything in none of them is insufficient. The severities are not theirs --
internet.nl reports pass or fail per check rather than a severity -- and are argued in
`pkg/tls/connection_analysis/rule_id_mappings`.

**A check that could not be run says so.** Ten of the eleven are answered by asking the server;
client-initiated renegotiation is not, because testing it means sending a ClientHello inside an
already-encrypted connection, and that needs a TLS record layer this deliberately does not
implement. It is reported as undetermined rather than omitted, because a check that said nothing
would be indistinguishable from one that passed. The same goes for a scan that runs out of
connections, or a server that stops answering partway through. Against a server that speaks only
TLS 1.3 the answer is known without asking -- the protocol removed renegotiation -- and it is
reported as not applicable.

Everything but OCSP stapling and 0-RTT is learned from handshakes that are deliberately never
completed: a ClientHello is written, the ServerHello read, and the connection dropped. That is why
`--connections` exists. Finding which cipher suites a server accepts means offering them all, noting
which it picks, removing that one and asking again, so the cost is one handshake per suite the
server accepts, per version it speaks.

### security.txt

```
altshift_web_security security-txt [-j] [-l {none,note,warning,error}] [-e] [-k] [-t SECS] HOST
```

```
$ altshift_web_security security-txt www.cloudflare.com
note      The security.txt has no Expires field  (security_txt_missing_expires)
          RFC 9116 section 2.5.5 requires one. Without it, a reader has no way to tell
          whether what the file says is still true ...
```

RFC 9116 defines the file a host serves at `/.well-known/security.txt` to say where a vulnerability
in it should be reported. The check looks there, then at the legacy top-level path, and reports
against what the RFC requires: the location, the https scheme and the content type; a Contact and an
Expires; an Expires that has not passed and is not more than the recommended year out; fields that
appear more often than they may; values that are not what their field requires; and a Canonical that
does not name where the file was found, which section 2.5.2 says makes the contents untrustworthy.

Nothing here is exploitable, and no rule is above `warning`. What it catches is a disclosure process
that does not work: most often an `Expires` that passed, which leaves a file that looks maintained
and that a conforming reader is required to disregard.

The parsing is `utils_go`'s `pkg/http/types/security_txt`, built on the RFC 9116 section 4 ABNF with
three documented deviations -- field order, bare LF line endings, and splitting each field into a
name and a value so that a malformed value can be reported as one. What the file *means* is
`utils_go`'s business; whether it is any good is this repository's.
