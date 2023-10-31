package main

import (
	"flag"
	"os"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	policyv1beta1 "github.com/aquasecurity/tracee/pkg/k8s/apis/tracee.aquasec.com/v1beta1"
	"github.com/aquasecurity/tracee/pkg/k8s/controller"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(policyv1beta1.AddToScheme(scheme))
}

type Config struct {
	MetricsAddr          string
	ProbeAddr            string
	TraceeNamespace      string
	TraceeName           string
	EnableLeaderElection bool
	LoggingOpts          zap.Options
}

func main() {
	config := parseConfig()

	// Set up a logger for the controller manager (prefix: "setup").
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&config.LoggingOpts)))

	// Create a controller manager that will take care of caching, syncing, and making
	// calls to the API server.

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: config.MetricsAddr},
		HealthProbeBindAddress: config.ProbeAddr,
		LeaderElection:         config.EnableLeaderElection,
		LeaderElectionID:       "ecaf1259.my.domain",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	// Register the PolicyReconciler with the controller manager. This will cause the
	// PolicyReconciler to watch for changes to Policy objects and deal with them.

	reconciler := &controller.PolicyReconciler{
		Client:          mgr.GetClient(),
		Scheme:          mgr.GetScheme(),
		TraceeNamespace: config.TraceeNamespace,
		TraceeName:      config.TraceeName,
	}
	if err := reconciler.SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "PolicyReconciler")
		os.Exit(1)
	}

	// Create health and readyz endpoints for the controller manager to report its health.

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	// Start the controller manager. This will block until the controller manager is
	// stopped or until a fatal error occurs.

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}

// parseConfig parses the command line flags and returns a Config struct
func parseConfig() Config {
	var cfg Config

	flag.StringVar(&cfg.MetricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&cfg.ProbeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.StringVar(&cfg.TraceeNamespace, "tracee-namespace", "tracee-system", "The namespace where Tracee is installed.")
	flag.StringVar(&cfg.TraceeName, "tracee-name", "tracee", "The name of the Tracee DaemonSet.")
	flag.BoolVar(&cfg.EnableLeaderElection, "leader-elect", false, "Enable leader election for controller manager. Enabling this will ensure there is only one active controller manager.")
	cfg.LoggingOpts = zap.Options{
		Development: true,
	}
	cfg.LoggingOpts.BindFlags(flag.CommandLine)

	flag.Parse()

	if namespace := os.Getenv("TRACEE_NAMESPACE"); namespace != "" {
		cfg.TraceeNamespace = namespace
	}
	if name := os.Getenv("TRACEE_NAME"); name != "" {
		cfg.TraceeName = name
	}

	return cfg
}
