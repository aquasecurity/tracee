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

	rootCmd.Flags().Bool(
		"no-containers",
		false,
		"\t\t\t\t\tDisable container info enrichment to events. Safeguard option.",
	)
	err = viper.BindPFlag("no-containers", rootCmd.Flags().Lookup("no-containers"))
	if err != nil {
		return errfmt.WrapError(err)
	}

	rootCmd.Flags().StringArray(
		"cri",
		[]string{},
		"<runtime:socket>\t\t\tDefine connected container runtimes",
	)
	err = viper.BindPFlag("cri", rootCmd.Flags().Lookup("cri"))
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

	// Buffer/Cache flags

	rootCmd.Flags().IntP(
		"perf-buffer-size",
		"b",
		1024, // 4 MB of contiguous pages
		"<size>\t\t\t\tSize, in pages, of the internal perf ring buffer used to submit events from the kernel",
	)
	err = viper.BindPFlag("perf-buffer-size", rootCmd.Flags().Lookup("perf-buffer-size"))
	if err != nil {
		return errfmt.WrapError(err)
	}

	rootCmd.Flags().Int(
		"blob-perf-buffer-size",
		1024, // 4 MB of contiguous pages
		"<size>\t\t\t\tSize, in pages, of the internal perf ring buffer used to send blobs from the kernel",
	)
	err = viper.BindPFlag("blob-perf-buffer-size", rootCmd.Flags().Lookup("blob-perf-buffer-size"))
	if err != nil {
		return errfmt.WrapError(err)
	}

	rootCmd.Flags().Int(
		"pipeline-channel-size",
		10000,
		"<size>\t\t\t\tSize, in event objects, of each pipeline stage's output channel",
	)
	err = viper.BindPFlag("pipeline-channel-size", rootCmd.Flags().Lookup("pipeline-channel-size"))
	if err != nil {
		return errfmt.WrapError(err)
	}

	rootCmd.Flags().StringArrayP(
		"cache",
		"a",
		[]string{"none"},
		"[type|mem-cache-size]\t\tControl event caching queues",
	)
	err = viper.BindPFlag("cache", rootCmd.Flags().Lookup("cache"))
	if err != nil {
		return errfmt.WrapError(err)
	}

	// Process Tree flags

	rootCmd.Flags().StringArrayP(
		"proctree",
		"t",
		[]string{"none"},
		"[process|thread]\t\t\tControl process tree options",
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

	rootCmd.Flags().StringArray(
		"server",
		[]string{""},
		`<type>.<option>=<value>		Configure HTTP or gRPC server options.  <type> is either "http" or "grpc".  Options include:
  									http: address, metrics, pprof, healthz, pyroscope
  									grpc: address`)

	err = viper.BindPFlag("server", rootCmd.Flags().Lookup("server"))
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
