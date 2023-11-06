package cmd

import (
	"context"
	"fmt"
	cmdcobra "github.com/aquasecurity/tracee/pkg/cmd/cobra"
	"github.com/aquasecurity/tracee/pkg/cmd/flags/server"
	"github.com/aquasecurity/tracee/pkg/version"
	"os"
	"os/signal"
	"syscall"

	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(analyze)

	// flags

	// TODO: decide if we want to bind this flag to viper, since we already have a similar
	// flag in analyze, conflicting with each other.
	// The same goes for the other flags (signatures-dir, rego), also in analyze.
	//
	// err := viper.BindPFlag("events", analyze.Flags().Lookup("events"))
	// if err != nil {
	// 	fmt.Fprintf(os.Stderr, "Error: %s\n", err)
	// 	os.Exit(1)
	// }

	// signatures-dir
	analyze.Flags().StringArray(
		"signatures-dir",
		[]string{},
		"Directory where to search for signatures in CEL (.yaml), OPA (.rego), and Go plugin (.so) formats",
	)

	// rego
	analyze.Flags().StringArray(
		"rego",
		[]string{},
		"Control event rego settings",
	)

	analyze.Flags().StringArrayP(
		"output",
		"o",
		[]string{"table"},
		"[json|none|webhook...]\t\tControl how and where output is printed",
	)

	// config is not bound to viper
	analyze.Flags().StringVar(
		&cfgFileFlag,
		"config",
		"",
		"<file>\t\t\t\tGlobal config file (yaml, json between others - see documentation)",
	)

	analyze.Flags().StringArrayP(
		"proctree",
		"t",
		[]string{"none"},
		"[process|thread]\t\t\tControl process tree options",
	)

	analyze.Flags().StringP(
		"input",
		"i",
		"json",
		"[json|rego]\t\tControl how and where input events stream is received",
	)

	// Scope/Event/Policy flags

	// scope is not bound to viper
	analyze.Flags().StringArrayP(
		"scope",
		"s",
		[]string{},
		"[uid|comm|container...]\t\tSelect workloads to trace by defining filter expressions",
	)

	// events is not bound to viper
	analyze.Flags().StringArrayP(
		"events",
		"e",
		[]string{},
		"[name|name.args.pathname...]\tSelect events to trace and event filters",
	)

	// policy is not bound to viper
	analyze.Flags().StringArrayP(
		"policy",
		"p",
		[]string{},
		"[file|dir]\t\t\t\tPath to a policy or directory with policies",
	)

	analyze.Flags().StringArrayP(
		"log",
		"l",
		[]string{"info"},
		"[debug|info|warn...]\t\tLogger options",
	)

	// Server flags

	analyze.Flags().Bool(
		server.MetricsEndpointFlag,
		false,
		"\t\t\t\t\tEnable metrics endpoint",
	)

	analyze.Flags().Bool(
		server.HealthzEndpointFlag,
		false,
		"\t\t\t\t\tEnable healthz endpoint",
	)

	analyze.Flags().Bool(
		server.PProfEndpointFlag,
		false,
		"\t\t\t\t\tEnable pprof endpoints",
	)

	analyze.Flags().Bool(
		server.PyroscopeAgentFlag,
		false,
		"\t\t\t\t\tEnable pyroscope agent",
	)

	analyze.Flags().String(
		server.HTTPListenEndpointFlag,
		":3366",
		"<url:port>\t\t\t\tListening address of the metrics endpoint server",
	)

	analyze.Flags().String(
		server.GRPCListenEndpointFlag,
		"", // disabled by default
		"<protocol:addr>\t\t\tListening address of the grpc server eg: tcp:4466, unix:/tmp/tracee.sock (default: disabled)",
	)
}

var analyze = &cobra.Command{
	Use:     "analyze input.json",
	Aliases: []string{},
	Short:   "Analyze past events with signature events [Experimental]",
	Long: `Analyze allow you to explore signature events with past events.

Tracee can be used to collect events and store it in a file. This file can be used as input to analyze.

eg:
tracee --events ptrace --output=json:events.json
tracee analyze --events anti_debugging events.json`,
	PreRun: func(cmd *cobra.Command, args []string) {
		if len(args) > 0 {
			// parse all flags
			if err := cmd.Flags().Parse(args); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %s\n", err)
				fmt.Fprintf(os.Stderr, "Run 'tracee analyze --help' for usage.\n")
				os.Exit(1)
			}
			if helpFlag {
				if err := cmd.Help(); err != nil {
					fmt.Fprintf(os.Stderr, "Error: %s\n", err)
					os.Exit(1)
				}
				os.Exit(0)
			}
			checkConfigFlag()
		}

		bindViperFlag(cmd, "signatures-dir")
		bindViperFlag(cmd, "rego")
		bindViperFlag(cmd, "output")
		bindViperFlag(cmd, "proctree")
		bindViperFlag(cmd, "input")
		bindViperFlag(cmd, "log")
		bindViperFlag(cmd, server.HealthzEndpointFlag)
		bindViperFlag(cmd, server.PProfEndpointFlag)
		bindViperFlag(cmd, server.PyroscopeAgentFlag)
		bindViperFlag(cmd, server.HTTPListenEndpointFlag)
		bindViperFlag(cmd, server.GRPCListenEndpointFlag)
		bindViperFlag(cmd, server.MetricsEndpointFlag)
	},
	Run: func(cmd *cobra.Command, args []string) {
		logger.Init(logger.NewDefaultLoggingConfig())

		runner, err := cmdcobra.GetTraceeAnalyzeRunner(cmd, version.GetVersion())
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			os.Exit(1)
		}

		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		// go func() {
		// 	select {
		// 	case <-runner.Producer.Done():
		// 		stop()
		// 	}
		// }()
		defer stop()

		err = runner.Run(ctx)
		if err != nil {
			logger.Fatalw("Tracee runner failed", "error", err)
			os.Exit(1)
		}

	},
	DisableFlagsInUseLine: true,
}
