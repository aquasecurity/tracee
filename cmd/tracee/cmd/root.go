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

	cmdcobra "github.com/aquasecurity/tracee/pkg/cmd/cobra"
	"github.com/aquasecurity/tracee/pkg/cmd/flags/server"
	"github.com/aquasecurity/tracee/pkg/cmd/initialize"
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/logger"
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
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			logger.Init(logger.NewDefaultLoggingConfig())
		},
		PreRun: func(cmd *cobra.Command, args []string) {
			if len(args) > 0 {
				// parse all flags
				if err := cmd.Flags().Parse(args); err != nil {
					fmt.Fprintf(os.Stderr, "Error: %s\n", err)
					fmt.Fprintf(os.Stderr, "Run 'tracee --help' for usage.\n")
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
			bindViperFlag(cmd, "output")
			bindViperFlag(cmd, "no-containers")
			bindViperFlag(cmd, "crs")
			bindViperFlag(cmd, "signatures-dir")
			bindViperFlag(cmd, "rego")
			bindViperFlag(cmd, "perf-buffer-size")
			bindViperFlag(cmd, "blob-perf-buffer-size")
			bindViperFlag(cmd, "cache")
			bindViperFlag(cmd, "proctree")
			bindViperFlag(cmd, server.HealthzEndpointFlag)
			bindViperFlag(cmd, server.PProfEndpointFlag)
			bindViperFlag(cmd, server.PyroscopeAgentFlag)
			bindViperFlag(cmd, server.HTTPListenEndpointFlag)
			bindViperFlag(cmd, server.GRPCListenEndpointFlag)
			bindViperFlag(cmd, "capabilities")
			bindViperFlag(cmd, "install-path")
			bindViperFlag(cmd, "log")
			bindViperFlag(cmd, server.MetricsEndpointFlag)
		},
		Run: func(cmd *cobra.Command, args []string) {
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
		"[name|name.args.pathname...]\tSelect events to trace and event filters",
	)

	// policy is not bound to viper
	rootCmd.Flags().StringArrayP(
		"policy",
		"p",
		[]string{},
		"[file|dir]\t\t\t\tPath to a policy or directory with policies",
	)

	// Output flags

	rootCmd.Flags().StringArrayP(
		"output",
		"o",
		[]string{"table"},
		"[json|none|webhook...]\t\tControl how and where output is printed",
	)

	// capture is not bound to viper
	rootCmd.Flags().StringArrayP(
		"capture",
		"c",
		[]string{},
		"[write|exec|network...]\t\tCapture artifacts that were written, executed or found to be suspicious",
	)

	// Config flag

	// config is not bound to viper
	rootCmd.Flags().StringVar(
		&cfgFileFlag,
		"config",
		"",
		"<file>\t\t\t\tGlobal config file (yaml, json between others - see documentation)",
	)

	// Container flags

	rootCmd.Flags().Bool(
		"no-containers",
		false,
		"\t\t\t\t\tDisable container info enrichment to events. Safeguard option.",
	)

	rootCmd.Flags().StringArray(
		"crs",
		[]string{},
		"<runtime:socket>\t\t\tDefine connected container runtimes",
	)

	// Signature flags

	rootCmd.Flags().StringArray(
		"signatures-dir",
		[]string{},
		"<dir>\t\t\t\tDirectories where to search for signatures in CEL (.yaml), OPA (.rego), and Go plugin (.so) formats",
	)

	rootCmd.Flags().StringArray(
		"rego",
		[]string{},
		"[partial-eval|aio]\t\t\tControl event rego settings",
	)

	// Buffer/Cache flags

	rootCmd.Flags().IntP(
		"perf-buffer-size",
		"b",
		1024, // 4 MB of contiguous pages
		"<size>\t\t\t\tSize, in pages, of the internal perf ring buffer used to submit events from the kernel",
	)

	rootCmd.Flags().Int(
		"blob-perf-buffer-size",
		1024, // 4 MB of contiguous pages
		"<size>\t\t\t\tSize, in pages, of the internal perf ring buffer used to send blobs from the kernel",
	)

	rootCmd.Flags().StringArrayP(
		"cache",
		"a",
		[]string{"none"},
		"[type|mem-cache-size]\t\tControl event caching queues",
	)

	rootCmd.Flags().StringArrayP(
		"proctree",
		"t",
		[]string{"none"},
		"[process|thread]\t\t\tControl process tree options",
	)

	// Server flags

	rootCmd.Flags().Bool(
		server.MetricsEndpointFlag,
		false,
		"\t\t\t\t\tEnable metrics endpoint",
	)

	rootCmd.Flags().Bool(
		server.HealthzEndpointFlag,
		false,
		"\t\t\t\t\tEnable healthz endpoint",
	)

	rootCmd.Flags().Bool(
		server.PProfEndpointFlag,
		false,
		"\t\t\t\t\tEnable pprof endpoints",
	)

	rootCmd.Flags().Bool(
		server.PyroscopeAgentFlag,
		false,
		"\t\t\t\t\tEnable pyroscope agent",
	)

	rootCmd.Flags().String(
		server.HTTPListenEndpointFlag,
		":3366",
		"<url:port>\t\t\t\tListening address of the metrics endpoint server",
	)

	rootCmd.Flags().String(
		server.GRPCListenEndpointFlag,
		"", // disabled by default
		"<protocol:addr>\t\t\tListening address of the grpc server eg: tcp:4466, unix:/tmp/tracee.sock (default: disabled)",
	)

	// Other flags

	rootCmd.Flags().StringArrayP(
		"capabilities",
		"C",
		[]string{},
		"[bypass|add|drop]\t\t\tDefine capabilities for tracee to run with",
	)

	rootCmd.Flags().String(
		"install-path",
		"/tmp/tracee",
		"<dir>\t\t\t\tPath where tracee will install or lookup it's resources",
	)

	rootCmd.Flags().StringArrayP(
		"log",
		"l",
		[]string{"info"},
		"[debug|info|warn...]\t\tLogger options",
	)

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

func bindViperFlag(cmd *cobra.Command, flag string) {
	err := viper.BindPFlag(flag, cmd.Flags().Lookup(flag))
	if err != nil {
		logger.Fatalw("Error binding viper flag", "flag", flag, "error", err)
	}
}
