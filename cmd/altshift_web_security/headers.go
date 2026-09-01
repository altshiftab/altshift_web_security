package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"

	headerAnalysis "github.com/altshiftab/altshift_web_security/pkg/http/header_analysis/analysis"
	"github.com/altshiftab/utils_go/pkg/cli/argument_parser"
	"github.com/altshiftab/utils_go/pkg/cli/argument_parser/option"
	"github.com/altshiftab/utils_go/pkg/sarif"
)

type headersSettings struct {
	target         string
	method         string
	requestHeaders []string
	insecure       bool
	timeoutSeconds int
	noFollow       bool
	minLevel       string
	exitCode       bool
	asJson         bool
}

func newHeadersCommand() *command {
	settings := &headersSettings{}

	subcommand := &command{
		parser: &argument_parser.Parser{
			ProgramName: programName + " headers",
			Command:     "headers",
			Description: "Analyse the security headers a URL serves.",
			Options: []option.Option{
				option.NewBoolOption(
					'j',
					"json",
					"Write the whole analysis as a SARIF log, with the rule table and the header value behind each finding.",
					false,
					&settings.asJson,
				),
				option.WithChoices(
					option.WithDefault(
						option.NewStringOption(
							'l',
							"min-level",
							"Withhold findings below this level.",
							false,
							&settings.minLevel,
						),
						string(sarif.LevelNone),
					),
					string(sarif.LevelNone),
					string(sarif.LevelNote),
					string(sarif.LevelWarning),
					string(sarif.LevelError),
				),
				option.NewBoolOption(
					'e',
					"exit-code",
					"Exit 1 when anything is reported, so that --min-level becomes a threshold to fail on.",
					false,
					&settings.exitCode,
				),
				option.WithDefault(
					option.NewStringOption('X', "method", "The request method.", false, &settings.method),
					http.MethodGet,
				),
				option.NewStringsOption(
					'H',
					"header",
					"A request header, written \"Name: value\". Repeatable.",
					false,
					&settings.requestHeaders,
				),
				option.NewBoolOption(
					'k',
					"insecure",
					"Request anyway when the server's certificate does not verify.",
					false,
					&settings.insecure,
				),
				option.WithDefault(
					option.NewIntOption(
						't',
						"timeout",
						"Seconds to wait for the response. Zero waits indefinitely.",
						false,
						&settings.timeoutSeconds,
					),
					"10",
				),
				option.NewBoolOption(
					0,
					"no-follow",
					"Analyse the first response rather than following redirects to the document.",
					false,
					&settings.noFollow,
				),
			},
			Positionals: []option.Option{
				option.WithMetavar(
					option.WithNargs(
						option.NewStringOption(
							0,
							"",
							"The URL to analyse. A raw header block is read from standard input when this is absent.",
							false,
							&settings.target,
						),
						option.NargsOptional,
					),
					"URL",
				),
			},
		},
	}

	subcommand.run = func(ctx context.Context) error { return runHeaders(ctx, settings, os.Stdin, os.Stdout) }

	return subcommand
}

func runHeaders(ctx context.Context, settings *headersSettings, in io.Reader, out io.Writer) error {
	if settings == nil {
		return nil
	}

	// A URL is fetched; its absence means the headers are being piped in, which is how a response
	// captured elsewhere -- a proxy log, a curl -D -- is analysed without going back to the server.
	var target string
	var header http.Header

	if settings.target == "" {
		data, err := io.ReadAll(in)
		if err != nil {
			return fmt.Errorf("io read all: %w", err)
		}

		header, err = parseHeaderBlock(data)
		if err != nil {
			return fmt.Errorf("parse header block: %w", err)
		}
	} else {
		requestHeader, err := parseRequestHeaders(settings.requestHeaders)
		if err != nil {
			return fmt.Errorf("parse request headers: %w", err)
		}

		target = normalizeUrl(settings.target)

		header, err = fetch(ctx, target, settings, requestHeader)
		if err != nil {
			return fmt.Errorf("fetch: %w", err)
		}
	}

	run, err := headerAnalysis.AnalyzeHeaders(header)
	if err != nil {
		return fmt.Errorf("analyze headers: %w", err)
	}
	if run == nil {
		return nil
	}

	// The filter applies to the SARIF log as well as to the report, so that what --json holds is
	// what was asked for rather than everything raised. The rule table follows the results it
	// describes, leaving the log internally consistent.
	run.Results = filterResults(run.Results, parseLevel(settings.minLevel))
	sortResults(run.Results)

	if run.Tool != nil && run.Tool.Driver != nil {
		run.Tool.Driver.Rules = pruneRules(run.Tool.Driver.Rules, run.Results)
	}

	if settings.asJson {
		if target != "" {
			run.Properties = sarif.PropertyBag{"url": target}
		}

		log := &sarif.Log{Schema: sarif.SchemaUri, Version: sarif.Version, Runs: []*sarif.Run{run}}
		if err := emit(out, log); err != nil {
			return fmt.Errorf("emit: %w", err)
		}
	} else if err := writeReport(out, run.Results); err != nil {
		return fmt.Errorf("write report: %w", err)
	}

	if settings.exitCode && len(run.Results) != 0 {
		return errFindings
	}

	return nil
}
