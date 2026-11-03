// Package header_block reads the header fields of a response captured somewhere else -- piped from
// curl, pasted from a browser's developer tools, copied out of a proxy log -- into the http.Header
// the analysis takes.
package header_block

import (
	"bufio"
	"fmt"
	"net/http"
	"net/textproto"
	"slices"
	"strings"

	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
)

// Parse reads the header fields of a response that was captured elsewhere.
//
// What arrives is whatever a person pasted or piped: a whole response beginning with its status
// line, or the fields alone; ending in a blank line, in a body or in nothing at all; with either line
// ending. All of it is accepted, because rejecting a paste over its last newline would serve nothing.
//
// A capture holding several responses -- curl -L through a redirect, or an interim 100 Continue --
// is read for its last, which is the response that was finally served. HTTP/2 pseudo-header fields
// such as ":status", which some tools list among the others, are not fields and are skipped.
//
// A block holding no fields is a validation error and a block that is not header fields a parse
// error. A parse error quotes the one line it stopped at, which is what a person needs to find it,
// and which may itself be a cookie or a credential: an error from here is shown to whoever pasted
// the block, not logged. The rest of the text is carried nowhere.
func Parse(text string) (http.Header, error) {
	text = strings.ReplaceAll(text, "\r\n", "\n")

	section := lastHeaderSection(strings.TrimLeft(text, "\n"))

	lines := slices.DeleteFunc(strings.Split(section, "\n"), func(line string) bool {
		return strings.HasPrefix(line, ":")
	})
	section = strings.Join(lines, "\n")

	if strings.TrimSpace(section) == "" {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: %w", altshiftErrors.ErrValidationError, empty_error.New("header block")),
		)
	}

	// The reader stops at a blank line, and treats reaching the end without one as the block being
	// cut short; supplying the terminator is what accepts a block that simply ended.
	section += "\n\n"

	mimeHeader, err := textproto.NewReader(bufio.NewReader(strings.NewReader(section))).ReadMIMEHeader()
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: textproto reader read mime header: %w", altshiftErrors.ErrParseError, err),
		)
	}

	// The reader accepts a name with a space in it, which a field name cannot hold (RFC 9112 section
	// 5.1) and which is what a line of prose with a colon in it reads as.
	for name := range mimeHeader {
		if strings.ContainsAny(name, " \t") {
			return nil, altshiftErrors.NewWithTrace(
				fmt.Errorf("%w: not a field name: %q", altshiftErrors.ErrParseError, name),
			)
		}
	}

	return http.Header(mimeHeader), nil
}

// lastHeaderSection is the header fields of the last response in text, without its status line and
// without anything after the blank line that ends them.
//
// A response begins with a status line, and is followed by another response only when what comes
// after its blank line begins with one too. Anything else there is a body, which ends the capture.
func lastHeaderSection(text string) string {
	if !strings.HasPrefix(text, "HTTP/") {
		section, _, _ := strings.Cut(text, "\n\n")
		return section
	}

	var section string
	for strings.HasPrefix(text, "HTTP/") {
		var rest string
		section, rest, _ = strings.Cut(text, "\n\n")
		_, section, _ = strings.Cut(section, "\n")
		text = strings.TrimLeft(rest, "\n")
	}

	return section
}
