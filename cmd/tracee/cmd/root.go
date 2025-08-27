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
	"github.com/aquasecurity/tracee/pkg/cmd/flags"
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
		PreRun: func(cmd *cobra.Command, args []string) {
			if len(args) > 0 {
				// parse all flags
				if err := cmd.Flags().Parse(args); err != nil {
					fmt.Fprintf(os.Stderr, "Error: %s\n", err)
					fmt.Fprintf(os.Stderr, "Run 'tracee --help' or 'tracee man' for usage.\n")
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

	// Output flags

	rootCmd.Flags().StringArrayP(
		"output",
		"o",
		[]string{"table"},
		"[json|none|webhook...]\t\tControl how and where output is printed",
	)
	err := viper.BindPFlag("output", rootCmd.Flags().Lookup("output"))
	if err != nil {
		return errfmt.WrapError(err)
	}

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

	rootCmd.Flags().StringArray(
		flags.ContainersFlag,
		[]string{},
		"Configure container enrichment and runtime sockets for container events enrichment (see documentation)",
	)
	err = viper.BindPFlag(flags.ContainersFlag, rootCmd.Flags().Lookup(flags.ContainersFlag))
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

	// Buffer flags

	defaultBufferPages := (4096 * 1024) / os.Getpagesize() // 4 MB of contiguous pages
	rootCmd.Flags().IntP(
		"perf-buffer-size",
		"b",
		defaultBufferPages,
		"<size>\t\t\t\tSize, in pages, of the internal perf ring buffer used to submit events from the kernel",
	)
	err = viper.BindPFlag("perf-buffer-size", rootCmd.Flags().Lookup("perf-buffer-size"))
	if err != nil {
		return errfmt.WrapError(err)
	}

	rootCmd.Flags().Int(
		"blob-perf-buffer-size",
		defaultBufferPages,
		"<size>\t\t\t\tSize, in pages, of the internal perf ring buffer used to send blobs from the kernel",
	)
	err = viper.BindPFlag("blob-perf-buffer-size", rootCmd.Flags().Lookup("blob-perf-buffer-size"))
	if err != nil {
		return errfmt.WrapError(err)
	}

	rootCmd.Flags().Int(
		"pipeline-channel-size",
		1000,
		"<size>\t\t\t\tSize, in event objects, of each pipeline stage's output channel",
	)
	err = viper.BindPFlag("pipeline-channel-size", rootCmd.Flags().Lookup("pipeline-channel-size"))
	if err != nil {
		return errfmt.WrapError(err)
	}

	// Process Tree flags

	rootCmd.Flags().StringArrayP(
		"proctree",
		"t",
		[]string{"source=none"},
		"[source=[events|signals|both]...]\tControl process tree options",
	)
	err = viper.BindPFlag("proctree", rootCmd.Flags().Lookup("proctree"))
	if err != nil {
		return errfmt.WrapError(err)
	}

	// DNS Cache flags

	rootCmd.Flags().StringArray(
		"dnscache",
		[]string{"none"},
		"\t\t\t\t\tEnable DNS Cache",
	)
	err = viper.BindPFlag("dnscache", rootCmd.Flags().Lookup("dnscache"))
	if err != nil {
		return errfmt.WrapError(err)
	}

	// Server flags

	rootCmd.Flags().Bool(
		server.MetricsEndpointFlag,
		false,
		"\t\t\t\t\tEnable metrics endpoint",
	)
	err = viper.BindPFlag(server.MetricsEndpointFlag, rootCmd.Flags().Lookup(server.MetricsEndpointFlag))
	if err != nil {
		return errfmt.WrapError(err)
	}

	rootCmd.Flags().Bool(
		server.HealthzEndpointFlag,
		false,
		"\t\t\t\t\tEnable healthz endpoint",
	)
	err = viper.BindPFlag(server.HealthzEndpointFlag, rootCmd.Flags().Lookup(server.HealthzEndpointFlag))
	if err != nil {
		return errfmt.WrapError(err)
	}

	rootCmd.Flags().Bool(
		server.PProfEndpointFlag,
		false,
		"\t\t\t\t\tEnable pprof endpoints",
	)
	err = viper.BindPFlag(server.PProfEndpointFlag, rootCmd.Flags().Lookup(server.PProfEndpointFlag))
	if err != nil {
		return errfmt.WrapError(err)
	}

	rootCmd.Flags().Bool(
		server.PyroscopeAgentFlag,
		false,
		"\t\t\t\t\tEnable pyroscope agent",
	)
	err = viper.BindPFlag(server.PyroscopeAgentFlag, rootCmd.Flags().Lookup(server.PyroscopeAgentFlag))
	if err != nil {
		return errfmt.WrapError(err)
	}

	rootCmd.Flags().String(
		server.HTTPListenEndpointFlag,
		":3366",
		"<url:port>\t\t\t\tListening address of the metrics endpoint server",
	)
	err = viper.BindPFlag(server.HTTPListenEndpointFlag, rootCmd.Flags().Lookup(server.HTTPListenEndpointFlag))
	if err != nil {
		return errfmt.WrapError(err)
	}

	rootCmd.Flags().String(
		server.GRPCListenEndpointFlag,
		"", // disabled by default
		"<protocol:addr>\t\t\tListening address of the grpc server eg: tcp:4466, unix:/tmp/tracee.sock (default: disabled)",
	)
	err = viper.BindPFlag(server.GRPCListenEndpointFlag, rootCmd.Flags().Lookup(server.GRPCListenEndpointFlag))
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

	rootCmd.Flags().String(
		"install-path",
		"/tmp/tracee",
		"<dir>\t\t\t\tPath where tracee will install or lookup it's resources",
	)
	err = viper.BindPFlag("install-path", rootCmd.Flags().Lookup("install-path"))
	if err != nil {
		return errfmt.WrapError(err)
	}

	rootCmd.Flags().StringArrayP(
		"log",
		"l",
		[]string{"info"},
		"[debug|info|warn...]\t\tLogger options",
	)
	err = viper.BindPFlag("log", rootCmd.Flags().Lookup("log"))
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
