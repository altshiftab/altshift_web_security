// Command altshift_web_security reports how a site is exposed to whoever visits it.
//
// One subcommand per layer that can be asked about from outside. Today that is the response headers
// a site serves; what it negotiates over TLS belongs beside it, which is why a single-subcommand
// program is a parser tree rather than a flat one.
//
// Output is a finding at a time, worst first, because that is the order they are worth reading in.
// Everything the analysis produced -- the rule table, the header value each finding was raised on --
// is on --json as a SARIF log, because that is what the library returns and a report meant for a
// person has nowhere to put it.
package main

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/altshiftab/utils_go/pkg/cli/argument_parser"
)

// programName is what the usage message and the error prefixes call this.
const programName = "altshift_web_security"

// errFindings ends a run that was asked to report findings through its exit status and found some.
// It leaves through the same status as a failure but without a message, the findings themselves
// being the output.
var errFindings = errors.New("findings were reported")

// command is one subcommand: a parser, and what to run once it has parsed.
//
// It wraps a parser rather than being one so that a run knows which subcommand was chosen. The
// parser dispatches by filling in the values bound to it, which tells the caller what was asked for
// but not which of the subcommands asked it.
type command struct {
	parser *argument_parser.Parser
	run    func(context.Context) error
	chosen bool
}

func (subcommand *command) GetCommand() string {
	return subcommand.parser.Command
}

// GetDescription lets the root parser describe this subcommand in its own help.
func (subcommand *command) GetDescription() string {
	return subcommand.parser.Description
}

// GetParser says what this wraps, so a completion can see the subcommand's options rather than only
// its name.
func (subcommand *command) GetParser() *argument_parser.Parser {
	return subcommand.parser
}

func (subcommand *command) ParseArgs(arguments []string) error {
	subcommand.chosen = true

	return subcommand.parser.ParseArgs(arguments)
}

// emit writes the value as indented JSON, which is what --json produces.
func emit(writer io.Writer, value any) error {
	data, err := json.Marshal(value, jsontext.WithIndent("  "))
	if err != nil {
		return fmt.Errorf("json marshal: %w", err)
	}

	if _, err := fmt.Fprintf(writer, "%s\n", data); err != nil {
		return fmt.Errorf("fprintf: %w", err)
	}

	return nil
}

func main() {
	subcommands := []*command{newHeadersCommand(), newTlsCommand(), newSecurityTxtCommand()}

	parsers := make([]argument_parser.Subparser, 0, len(subcommands))
	for _, subcommand := range subcommands {
		parsers = append(parsers, subcommand)

		// A subcommand's own declaration being wrong is a mistake in this program rather than in
		// what the user typed, so it is caught at startup rather than on the parse that happens to
		// reach it.
		if err := subcommand.parser.Validate(); err != nil {
			fmt.Fprintf(
				os.Stderr,
				"%s: error: the %s parser's own declaration is wrong: %v\n",
				programName, subcommand.parser.Command, err,
			)
			os.Exit(2)
		}
	}

	parser := &argument_parser.Parser{
		ProgramName: programName,
		Description: "Report how a site is exposed to whoever visits it.",
		Parsers:     parsers,
	}

	if err := parser.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "%s: error: the parser's own declaration is wrong: %v\n", programName, err)
		os.Exit(2)
	}

	// --completion is answered inside ParseOrExit, which leaves through status 0 the way --help
	// does, so nothing here has to know about it.
	parser.ParseOrExit()

	var chosen *command
	for _, subcommand := range subcommands {
		if subcommand.chosen {
			chosen = subcommand
			break
		}
	}

	// No subcommand at all is not an error the parser catches, because the root declares no options
	// of its own; the help is the useful answer.
	if chosen == nil {
		if err := parser.ParseArgs([]string{"--help"}); err != nil {
			fmt.Fprintf(os.Stderr, "%s: error: %v\n", programName, err)
		}
		os.Exit(2)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := chosen.run(ctx); err != nil {
		// --exit-code asked for the status, not for a diagnostic: the findings were the output and
		// they have already been written.
		if errors.Is(err, errFindings) {
			os.Exit(1)
		}

		fmt.Fprintf(os.Stderr, "%s: %s: error: %v\n", programName, chosen.parser.Command, err)
		os.Exit(1)
	}
}
