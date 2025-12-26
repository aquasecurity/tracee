package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/aquasecurity/tracee/common/errfmt"
	"github.com/aquasecurity/tracee/common/logger"
	cmdcobra "github.com/aquasecurity/tracee/pkg/cmd/cobra"
	"github.com/aquasecurity/tracee/pkg/cmd/flags"
	"github.com/aquasecurity/tracee/pkg/cmd/initialize"
	"github.com/aquasecurity/tracee/pkg/version"
)

var (
	cfgFileFlag string
	helpFlag    bool

	rootCmd = &cobra.Command{
		Use:   "tracee",
		Short: "Trace OS events and syscalls using eBPF",
		Long: `Tracee uses eBPF technology to tap into your system and give you
access to hundreds of events that help you understand how your system behaves.`,
		DisableFlagParsing: true, // in order to have fine grained control over flags parsing
		PreRun: func(cmd *cobra.Command, args []string) {
			if len(args) > 0 {
				// parse all flags
				if err := cmd.Flags().Parse(args); err != nil {
					fmt.Fprintf(os.Stderr, "Error: %s\n", err)
					fmt.Fprint(os.Stderr, "Run 'tracee --help' or 'tracee man' for usage.\n")
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
			initialize.SetLibbpfgoCallbacks()

			runner, err := cmdcobra.GetTraceeRunner(cmd, version.GetVersion())
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
		SilenceUsage:  true,
		SilenceErrors: true,
	}
)

func initCmd() error {
	rootCmd.SetOut(os.Stdout)
	rootCmd.SetErr(os.Stderr)

	// disable default help command (./tracee help) overriding it with an empty command
	rootCmd.SetHelpCommand(&cobra.Command{})

	// help is not bound to viper
	rootCmd.Flags().BoolVarP(
		&helpFlag,
		"help",
		"h",
		false,
		"",
	)

	// Scope/Event/Policy flags

	// scope is not bound to viper
	rootCmd.Flags().StringArrayP(
		"scope",
		"s",
		[]string{},
		"[uid|comm|container...]\t\tSelect workloads to trace by defining filter expressions",
	)

	// events is not bound to viper
	rootCmd.Flags().StringArrayP(
		"events",
		"e",
		[]string{},
		"[name|name.data.pathname...]\tSelect events to trace and event filters",
	)

	// policy is not bound to viper
	rootCmd.Flags().StringArrayP(
		"policy",
		"p",
		[]string{},
		"[file|dir]\t\t\t\tPath to a policy or directory with policies",
	)

	// Runtime flags

	rootCmd.Flags().StringArrayP(
		flags.RuntimeFlag,
		"r",
		[]string{"workdir=" + flags.WorkdirDefault},
		fmt.Sprintf("[workdir=%s]\t\tControl runtime configurations", flags.WorkdirDefault),
	)
	err := viper.BindPFlag(flags.RuntimeFlag, rootCmd.Flags().Lookup(flags.RuntimeFlag))
	if err != nil {
		return errfmt.WrapError(err)
	}

	// Output flags

	rootCmd.Flags().StringArrayP(
		"output",
		"o",
		[]string{"table"},
		"[json|none|webhook...]\t\tControl how and where output is printed",
	)
	err = viper.BindPFlag("output", rootCmd.Flags().Lookup("output"))
	if err != nil {
		return errfmt.WrapError(err)
	}

	// artifacts is bound to viper
	rootCmd.Flags().StringArrayP(
		flags.ArtifactsFlag,
		"a",
		[]string{},
		"[file-write|executable...]\t\tCapture artifacts that were written, executed or found to be suspicious",
	)
	err = viper.BindPFlag(flags.ArtifactsFlag, rootCmd.Flags().Lookup(flags.ArtifactsFlag))
	if err != nil {
		return errfmt.WrapError(err)
	}

	// Config flag

	// config is not bound to viper
	rootCmd.Flags().StringVarP(
		&cfgFileFlag,
		"config",
		"c",
		"",
		"<file>\t\t\t\tGlobal config file (yaml, json between others - see documentation)",
	)

	// Container flags

	rootCmd.Flags().StringArray(
		flags.EnrichmentFlag,
		[]string{},
		"[container|resolve-fd...]\t\tConfigure enrichment for container events and other enrichment features",
	)
	err = viper.BindPFlag(flags.EnrichmentFlag, rootCmd.Flags().Lookup(flags.EnrichmentFlag))
	if err != nil {
		return errfmt.WrapError(err)
	}

	// Signature flags

	rootCmd.Flags().StringArray(
		"signatures-dir",
		[]string{},
		"<dir>\t\t\t\tDirectories where to search for signatures in Go plugin (.so) format",
	)
	err = viper.BindPFlag("signatures-dir", rootCmd.Flags().Lookup("signatures-dir"))
	if err != nil {
		return errfmt.WrapError(err)
	}

	rootCmd.Flags().Bool(
		"no-signatures",
		false,
		"\t\t\t\t\tDisable signature processing while keeping the same events loaded (for performance testing)",
	)
	err = viper.BindPFlag("no-signatures", rootCmd.Flags().Lookup("no-signatures"))
	if err != nil {
		return errfmt.WrapError(err)
	}
	err = rootCmd.Flags().MarkHidden("no-signatures")
	if err != nil {
		return errfmt.WrapError(err)
	}

	// Detector flags

	rootCmd.Flags().StringArray(
		flags.DetectorsFlag,
		[]string{},
		"[yaml-dir=<dir>]\t\t\tConfigure YAML detector search directories",
	)
	err = viper.BindPFlag(flags.DetectorsFlag, rootCmd.Flags().Lookup(flags.DetectorsFlag))
	if err != nil {
		return errfmt.WrapError(err)
	}

	// Buffer flags

	rootCmd.Flags().StringArrayP(
		flags.BuffersFlag,
		"b",
		[]string{
			fmt.Sprintf("kernel.events=%d", flags.GetDefaultPerfBufferSize()),
			fmt.Sprintf("kernel.control-plane=%d", flags.GetDefaultPerfBufferSize()),
			fmt.Sprintf("kernel.artifacts=%d", flags.GetDefaultPerfBufferSize()),
			"pipeline=1000",
		},
		"[kernel.events|...]\t\tSize for kernel and user buffers",
	)
	err = viper.BindPFlag(flags.BuffersFlag, rootCmd.Flags().Lookup(flags.BuffersFlag))
	if err != nil {
		return errfmt.WrapError(err)
	}

	// Stores flags

	rootCmd.Flags().StringArray(
		flags.StoresFlag,
		[]string{},
		"[process|dns...]\t\t\tStores configurations",
	)
	err = viper.BindPFlag(flags.StoresFlag, rootCmd.Flags().Lookup(flags.StoresFlag))
	if err != nil {
		return errfmt.WrapError(err)
	}

	// Server flags

	rootCmd.Flags().StringArray(
		flags.ServerFlag,
		[]string{},
		"[http-address|grpc-address...]\tConfigure server options and endpoints")

	err = viper.BindPFlag(flags.ServerFlag, rootCmd.Flags().Lookup(flags.ServerFlag))
	if err != nil {
		return errfmt.WrapError(err)
	}

	// Other flags

	rootCmd.Flags().StringArrayP(
		"capabilities",
		"C",
		[]string{},
		"[bypass|add|drop]\t\t\tDefine capabilities for tracee to run with",
	)
	err = viper.BindPFlag("capabilities", rootCmd.Flags().Lookup("capabilities"))
	if err != nil {
		return errfmt.WrapError(err)
	}

	rootCmd.Flags().StringArrayP(
		flags.LoggingFlag,
		flags.LoggingFlagShort,
		[]string{flags.DefaultLogLevelFlag},
		"[debug|info|warn...]\t\tLogger options",
	)
	err = viper.BindPFlag(flags.LoggingFlag, rootCmd.Flags().Lookup(flags.LoggingFlag))
	if err != nil {
		return errfmt.WrapError(err)
	}

	rootCmd.Flags().SortFlags = false

	return nil
}

func checkConfigFlag() {
	if cfgFileFlag == "" {
		return
	}

	cfgFile, err := filepath.Abs(cfgFileFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", errfmt.WrapError(err))
		os.Exit(1)
	}

	_, err = os.Stat(cfgFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", errfmt.WrapError(err))
		os.Exit(1)
	}

	viper.SetConfigFile(cfgFile)
	if err := viper.ReadInConfig(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", errfmt.WrapError(err))
		os.Exit(1)
	}
}

func Execute() error {
	if err := initCmd(); err != nil {
		return err
	}

	return rootCmd.Execute()
}
