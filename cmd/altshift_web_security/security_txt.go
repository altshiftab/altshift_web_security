package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	securityTxtAnalysis "github.com/altshiftab/altshift_web_security/pkg/http/security_txt_analysis/analysis"
	"github.com/altshiftab/altshift_web_security/pkg/http/security_txt_analysis/retrieval"
	"github.com/altshiftab/utils_go/pkg/cli/argument_parser"
	"github.com/altshiftab/utils_go/pkg/cli/argument_parser/option"
	"github.com/altshiftab/utils_go/pkg/sarif"
)

type securityTxtSettings struct {
	target         string
	timeoutSeconds int
	insecure       bool
	minLevel       string
	exitCode       bool
	asJson         bool
}

func newSecurityTxtCommand() *command {
	settings := &securityTxtSettings{}

	subcommand := &command{
		parser: &argument_parser.Parser{
			ProgramName: programName + " security-txt",
			Command:     "security-txt",
			Description: "Analyse the security.txt a host serves.",
			Options: []option.Option{
				option.NewBoolOption(
					'j',
					"json",
					"Write the whole analysis as a SARIF log, with the rule table and the particulars behind each finding.",
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
				option.NewBoolOption(
					'k',
					"insecure",
					"Fetch anyway when the server's certificate does not verify.",
					false,
					&settings.insecure,
				),
				option.WithDefault(
					option.NewIntOption(
						't',
						"timeout",
						"Seconds to wait for each request.",
						false,
						&settings.timeoutSeconds,
					),
					"10",
				),
			},
			Positionals: []option.Option{
				option.WithMetavar(
					option.NewStringOption(
						0,
						"",
						"The host to analyse. Its security.txt is looked for at the well-known path and then at the "+
							"legacy top-level one.",
						true,
						&settings.target,
					),
					"HOST",
				),
			},
		},
	}

	subcommand.run = func(ctx context.Context) error { return runSecurityTxt(ctx, settings, os.Stdout) }

	return subcommand
}

func runSecurityTxt(ctx context.Context, settings *securityTxtSettings, out io.Writer) error {
	if settings == nil {
		return nil
	}

	// The host is taken the same way the tls subcommand takes it, so that a URL
	// pasted out of a browser works in both. The port is not used: RFC 9116 puts
	// the file on the host's ordinary https service.
	host, _, err := splitTarget(settings.target)
	if err != nil {
		return fmt.Errorf("split target: %w", err)
	}

	retrievalSettings := retrieval.DefaultSettings()
	retrievalSettings.Insecure = settings.insecure

	if settings.timeoutSeconds > 0 {
		retrievalSettings.Timeout = time.Duration(settings.timeoutSeconds) * time.Second
	}

	found, err := retrieval.Retrieve(ctx, host, retrievalSettings)
	if err != nil {
		return fmt.Errorf("retrieve: %w", err)
	}

	run, err := securityTxtAnalysis.Analyze(found)
	if err != nil {
		return fmt.Errorf("analyze: %w", err)
	}

	if run == nil {
		return nil
	}

	run.Results = filterResults(run.Results, parseLevel(settings.minLevel))
	sortResults(run.Results)

	if run.Tool != nil && run.Tool.Driver != nil {
		run.Tool.Driver.Rules = pruneRules(run.Tool.Driver.Rules, run.Results)
	}

	if settings.asJson {
		run.Properties = sarif.PropertyBag{"host": host}

		if found.Found != nil {
			run.Properties["url"] = found.Found.FinalUrl
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
