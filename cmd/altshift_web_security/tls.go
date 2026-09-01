package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	tlsAnalysis "github.com/altshiftab/altshift_web_security/pkg/tls/connection_analysis/analysis"
	"github.com/altshiftab/altshift_web_security/pkg/tls/observation"
	"github.com/altshiftab/altshift_web_security/pkg/tls/probe"
	"github.com/altshiftab/utils_go/pkg/cli/argument_parser"
	"github.com/altshiftab/utils_go/pkg/cli/argument_parser/option"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/sarif"
)

type tlsSettings struct {
	target         string
	serverName     string
	timeoutSeconds int
	connections    int
	concurrency    int
	minLevel       string
	exitCode       bool
	asJson         bool
}

func newTlsCommand() *command {
	settings := &tlsSettings{}

	subcommand := &command{
		parser: &argument_parser.Parser{
			ProgramName: programName + " tls",
			Command:     "tls",
			Description: "Analyse the TLS a host negotiates.",
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
				option.NewStringOption(
					0,
					"sni",
					"The name to send as SNI. The host is sent when this is absent.",
					false,
					&settings.serverName,
				),
				option.WithDefault(
					option.NewIntOption(
						't',
						"timeout",
						"Seconds to wait for each handshake.",
						false,
						&settings.timeoutSeconds,
					),
					"5",
				),
				option.WithDefault(
					option.NewIntOption(
						0,
						"connections",
						"The most handshakes one run may make. Finding which cipher suites a server accepts costs one "+
							"handshake per suite, so a scan that would cost more than this stops and says which "+
							"checks it left unfinished.",
						false,
						&settings.connections,
					),
					"250",
				),
				option.WithDefault(
					option.NewIntOption(
						0,
						"concurrency",
						"How many handshakes may be in flight at once.",
						false,
						&settings.concurrency,
					),
					"4",
				),
			},
			Positionals: []option.Option{
				option.WithMetavar(
					option.NewStringOption(
						0,
						"",
						"The host to analyse, with an optional port. Port 443 is used when none is given.",
						true,
						&settings.target,
					),
					"HOST[:PORT]",
				),
			},
		},
	}

	subcommand.run = func(ctx context.Context) error { return runTls(ctx, settings, os.Stdout) }

	return subcommand
}

func runTls(ctx context.Context, settings *tlsSettings, out io.Writer) error {
	if settings == nil {
		return nil
	}

	host, port, err := splitTarget(settings.target)
	if err != nil {
		return fmt.Errorf("split target: %w", err)
	}

	target := &observation.Target{Host: host, Port: port, ServerName: settings.serverName}

	probeSettings := probe.DefaultSettings()
	probeSettings.ConnectTimeout = time.Duration(settings.timeoutSeconds) * time.Second
	probeSettings.HandshakeTimeout = probeSettings.ConnectTimeout

	if settings.connections > 0 {
		probeSettings.MaxConnections = settings.connections
	}

	if settings.concurrency > 0 {
		probeSettings.Concurrency = settings.concurrency
	}

	result, err := probe.Probe(ctx, target, probeSettings)
	if err != nil {
		return fmt.Errorf("probe: %w", err)
	}

	run, err := tlsAnalysis.AnalyzeConnection(result)
	if err != nil {
		return fmt.Errorf("analyze connection: %w", err)
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
		run.Properties = sarif.PropertyBag{
			"host": host,
			"port": port,
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

// splitTarget reads "host" or "host:port", defaulting to the port a browser would
// use. A bare IPv6 address has to be bracketed to be told from a host and a port,
// which is what net.SplitHostPort decides.
func splitTarget(target string) (string, int, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", 0, altshiftErrors.NewWithTrace(empty_error.New("target"))
	}

	// A URL is a reasonable thing to paste, and the scheme is not part of a host.
	if _, rest, found := strings.Cut(target, "://"); found {
		target = rest
		target, _, _ = strings.Cut(target, "/")
	}

	if !strings.Contains(target, ":") || (strings.Contains(target, ":") && strings.HasPrefix(target, "[")) {
		if !strings.Contains(target, "]:") {
			return strings.Trim(target, "[]"), 443, nil
		}
	}

	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		// A bare IPv6 address holds colons but no port.
		if strings.Count(target, ":") > 1 {
			return target, 443, nil
		}

		return "", 0, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: net split host port: %w", altshiftErrors.ErrParseError, err),
			target,
		)
	}

	port, err := strconv.Atoi(portText)
	if err != nil {
		return "", 0, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: strconv atoi: %w", altshiftErrors.ErrParseError, err),
			portText,
		)
	}

	if port < 1 || port > 65535 {
		return "", 0, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: the port is outside the range of a port", altshiftErrors.ErrValidationError),
			port,
		)
	}

	return host, port, nil
}
