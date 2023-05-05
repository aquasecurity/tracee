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
)

var (
	cfgFile string
	rootCmd = &cobra.Command{
		Use:   "tracee",
		Short: "Trace OS events and syscalls using eBPF",
		Long: `Tracee uses eBPF technology to tap into your system and give you
access to hundreds of events that help you understand how your system behaves.`,
		Run: func(cmd *cobra.Command, args []string) {
			logger.Init(logger.NewDefaultLoggingConfig())
			initialize.SetLibbpfgoCallbacks()

			runner, err := cmdcobra.GetTraceeRunner(cmd, version)
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

	cobra.OnInitialize(initConfig)

	hfFallback := rootCmd.HelpFunc()
	// Override default help function to support help for flags.
	// Since for commands the usage is tracee help <command>, for flags
	// the usage is tracee --help <flag>.
	// e.g. tracee --help filter
	//      tracee -h filter
	rootCmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		if len(args) > 1 && (args[0] == "--help" || args[0] == "-h") {
			flagHelp := flags.GetHelpString(args[1], true)
			if flagHelp != "" {
				fmt.Fprintf(os.Stdout, "%s\n", flagHelp)
				os.Exit(0)
			}
		}

		// If flag help was not found, fallback to default help function
		hfFallback(cmd, args)
	})

	// Filter/Policy flags

	// filter is not bound to viper
	rootCmd.Flags().StringArrayP(
		"filter",
		"f",
		[]string{},
		"Select events to trace by defining filter expressions",
	)

	// policy is not bound to viper
	rootCmd.Flags().StringArrayP(
		"policy",
		"p",
		[]string{},
		"Path to a policy or directory with policies",
	)

	// Output flags

	rootCmd.Flags().StringArrayP(
		"output",
		"o",
		[]string{"table"},
		"Control how and where output is printed",
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
		"Capture artifacts that were written, executed or found to be suspicious",
	)

	// Config flag

	// config is not bound to viper
	rootCmd.Flags().StringVar(
		&cfgFile,
		"config",
		"",
		"Global config file (yaml, json between others - see documentation)",
	)

	// Container flags

	rootCmd.Flags().Bool(
		"containers",
		false,
		"Enable container info enrichment to events. This feature is experimental and may cause unexpected behavior in the pipeline",
	)
	err = viper.BindPFlag("containers", rootCmd.Flags().Lookup("containers"))
	if err != nil {
		return errfmt.WrapError(err)
	}

	rootCmd.Flags().StringArray(
		"crs",
		[]string{},
		"Define connected container runtimes",
	)
	err = viper.BindPFlag("crs", rootCmd.Flags().Lookup("crs"))
	if err != nil {
		return errfmt.WrapError(err)
	}

	// Signature flags

	rootCmd.Flags().String(
		"signatures-dir",
		"",
		"Directory where to search for signatures in CEL (.yaml), OPA (.rego), and Go plugin (.so) formats",
	)
	err = viper.BindPFlag("signatures-dir", rootCmd.Flags().Lookup("signatures-dir"))
	if err != nil {
		return errfmt.WrapError(err)
	}

	rootCmd.Flags().StringArray(
		"rego",
		[]string{},
		"Control event rego settings",
	)
	err = viper.BindPFlag("rego", rootCmd.Flags().Lookup("rego"))
	if err != nil {
		return errfmt.WrapError(err)
	}

	// Buffer/Cache flags

	rootCmd.Flags().IntP(
		"perf-buffer-size",
		"b",
		1024, // 4 MB of contiguous pages
		"Size, in pages, of the internal perf ring buffer used to submit events from the kernel",
	)
	err = viper.BindPFlag("perf-buffer-size", rootCmd.Flags().Lookup("perf-buffer-size"))
	if err != nil {
		return errfmt.WrapError(err)
	}

	rootCmd.Flags().Int(
		"blob-perf-buffer-size",
		1024, // 4 MB of contiguous pages
		"Size, in pages, of the internal perf ring buffer used to send blobs from the kernel",
	)
	err = viper.BindPFlag("blob-perf-buffer-size", rootCmd.Flags().Lookup("blob-perf-buffer-size"))
	if err != nil {
		return errfmt.WrapError(err)
	}

	rootCmd.Flags().StringArrayP(
		"cache",
		"a",
		[]string{"none"},
		"Control event caching queues",
	)
	err = viper.BindPFlag("cache", rootCmd.Flags().Lookup("cache"))
	if err != nil {
		return errfmt.WrapError(err)
	}

	// Server flags

	// TODO: add webhook

	rootCmd.Flags().Bool(
		server.MetricsEndpointFlag,
		false,
		"Enable metrics endpoint",
	)
	err = viper.BindPFlag(server.MetricsEndpointFlag, rootCmd.Flags().Lookup(server.MetricsEndpointFlag))
	if err != nil {
		return errfmt.WrapError(err)
	}

	rootCmd.Flags().Bool(
		server.HealthzEndpointFlag,
		false,
		"Enable healthz endpoint",
	)
	err = viper.BindPFlag(server.HealthzEndpointFlag, rootCmd.Flags().Lookup(server.HealthzEndpointFlag))
	if err != nil {
		return errfmt.WrapError(err)
	}

	rootCmd.Flags().Bool(
		server.PProfEndpointFlag,
		false,
		"Enable pprof endpoints",
	)
	err = viper.BindPFlag(server.PProfEndpointFlag, rootCmd.Flags().Lookup(server.PProfEndpointFlag))
	if err != nil {
		return errfmt.WrapError(err)
	}

	rootCmd.Flags().Bool(
		server.PyroscopeAgentFlag,
		false,
		"Enable pyroscope agent",
	)
	err = viper.BindPFlag(server.PyroscopeAgentFlag, rootCmd.Flags().Lookup(server.PyroscopeAgentFlag))
	if err != nil {
		return errfmt.WrapError(err)
	}

	rootCmd.Flags().String(
		server.ListenEndpointFlag,
		":3366",
		"Listening address of the metrics endpoint server",
	)
	err = viper.BindPFlag(server.ListenEndpointFlag, rootCmd.Flags().Lookup(server.ListenEndpointFlag))
	if err != nil {
		return errfmt.WrapError(err)
	}

	// Other flags

	rootCmd.Flags().StringArrayP(
		"capabilities",
		"C",
		[]string{},
		"Define capabilities for tracee to run with",
	)
	err = viper.BindPFlag("capabilities", rootCmd.Flags().Lookup("capabilities"))
	if err != nil {
		return errfmt.WrapError(err)
	}

	rootCmd.Flags().String(
		"install-path",
		"/tmp/tracee",
		"Path where tracee will install or lookup it's resources",
	)
	err = viper.BindPFlag("install-path", rootCmd.Flags().Lookup("install-path"))
	if err != nil {
		return errfmt.WrapError(err)
	}

	rootCmd.Flags().StringArrayP(
		"log",
		"l",
		[]string{"info"},
		"Logger options",
	)
	err = viper.BindPFlag("log", rootCmd.Flags().Lookup("log"))
	if err != nil {
		return errfmt.WrapError(err)
	}

	rootCmd.Flags().SortFlags = false

	return nil
}

func initConfig() {
	if cfgFile == "" {
		return
	}

	cfgFile, err := filepath.Abs(cfgFile)
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

func Execute() {
	if err := initCmd(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		return
	}

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		return
	}
}
