package cmd

import (
	"context"
	"fmt"
	cmdcobra "github.com/aquasecurity/tracee/pkg/cmd/cobra"
	"github.com/aquasecurity/tracee/pkg/version"
	"github.com/spf13/viper"
	"os"
	"os/signal"
	"syscall"

	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(analyze)

	var err error

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
	err = viper.BindPFlag("signatures-dir", analyze.Flags().Lookup("signatures-dir"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}

	// rego
	analyze.Flags().StringArray(
		"rego",
		[]string{},
		"Control event rego settings",
	)
	err = viper.BindPFlag("rego", analyze.Flags().Lookup("rego"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}

	analyze.Flags().StringArrayP(
		"output",
		"o",
		[]string{"table"},
		"[json|none|webhook...]\t\tControl how and where output is printed",
	)
	err = viper.BindPFlag("output", analyze.Flags().Lookup("output"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

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
	err = viper.BindPFlag("proctree", analyze.Flags().Lookup("proctree"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	analyze.Flags().StringP(
		"input",
		"i",
		"json",
		"[json|rego]\t\tControl how and where input events stream is received",
	)
	err = viper.BindPFlag("input", analyze.Flags().Lookup("input"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

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
	err = viper.BindPFlag("log", analyze.Flags().Lookup("log"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
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
	},
	Run: func(cmd *cobra.Command, args []string) {
		logger.Init(logger.NewDefaultLoggingConfig())

		runner, err := cmdcobra.GetTraceeAnalyzeRunner(cmd, version.GetVersion())
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			os.Exit(1)
		}

		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()

		err = runner.Run(ctx)
		if err != nil {
			logger.Fatalw("Tracee runner failed", "error", err)
			os.Exit(1)
		}

	},
	DisableFlagsInUseLine: true,
}
