package controller

import (
	"context"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/aquasecurity/tracee/pkg/k8s/apis/tracee.aquasec.com/v1beta1"
)

// restartDaemonSet restarts the Tracee DaemonSet by adding a timestamp annotation to the pod template.
// This uses the same strategy as kubectl rollout restart, causing the daemonset controller to rollout
// a new daemonset.
func restartDaemonSet(ctx context.Context, c client.Client, namespace, name string) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var ds appsv1.DaemonSet

	key := client.ObjectKey{
		Namespace: namespace,
		Name:      name,
	}
	if err := c.Get(ctx, key, &ds); err != nil {
		logger.Error(err, "unable to fetch daemonset")
		return ctrl.Result{}, err
	}

	if ds.Spec.Template.Annotations == nil {
		ds.Spec.Template.Annotations = make(map[string]string)
	}

	ds.Spec.Template.Annotations["tracee-operator-restarted"] = time.Now().String()

	if err := c.Update(ctx, &ds); err != nil {
		logger.Error(err, "unable to update daemonset")
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// PolicyReconciler is the main controller for the Tracee Policy CRD. It is responsible
// for updating the Tracee DaemonSet whenever a change is detected in a TraceePolicy
// object.
type PolicyReconciler struct {
	client.Client
	Scheme          *runtime.Scheme
	TraceeNamespace string
	TraceeName      string
}

// +kubebuilder:rbac:groups=tracee.aquasec.com,resources=policies,verbs=get;list;watch;
// +kubebuilder:rbac:groups=apps,resources=daemonsets,verbs=get;list;watch;patch;update;

// Reconcile is where the reconciliation logic resides. Every time a change is detected in
// a v1beta1.Policy object, this function will be called. It will update the Tracee
// DaemonSet, so that the Tracee pods will be restarted with the new policy.
func (r *PolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	return restartDaemonSet(ctx, r.Client, r.TraceeNamespace, r.TraceeName)
}

// SetupWithManager is responsible for connecting the PolicyReconciler to the main
// controller manager. It tells the manager that for changes in v1beta1Policy objects, the
// PolicyReconciler should be invoked.
func (r *PolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1beta1.Policy{}).
		Complete(r)
}

// DetectorReconciler is the controller for the Tracee Detector CRD. It is responsible
// for updating the Tracee DaemonSet whenever a change is detected in a Detector object.
type DetectorReconciler struct {
	client.Client
	Scheme          *runtime.Scheme
	TraceeNamespace string
	TraceeName      string
}

// +kubebuilder:rbac:groups=tracee.aquasec.com,resources=detectors,verbs=get;list;watch;
// +kubebuilder:rbac:groups=apps,resources=daemonsets,verbs=get;list;watch;patch;update;

// Reconcile is where the reconciliation logic resides. Every time a change is detected in
// a v1beta1.Detector object, this function will be called. It will update the Tracee
// DaemonSet, so that the Tracee pods will be restarted with the new detector.
func (r *DetectorReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	return restartDaemonSet(ctx, r.Client, r.TraceeNamespace, r.TraceeName)
}

// SetupWithManager is responsible for connecting the DetectorReconciler to the main
// controller manager. It tells the manager that for changes in v1beta1.Detector objects, the
// DetectorReconciler should be invoked.
func (r *DetectorReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1beta1.Detector{}).
		Complete(r)
}

// ConfigMapReconciler is the controller for the Tracee ConfigMap. It is responsible
// for updating the Tracee DaemonSet whenever a change is detected in the Tracee ConfigMap.
type ConfigMapReconciler struct {
	client.Client
	Scheme          *runtime.Scheme
	TraceeNamespace string
	TraceeName      string
	ConfigMapName   string
}

// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;
// +kubebuilder:rbac:groups=apps,resources=daemonsets,verbs=get;list;watch;patch;update;

// Reconcile is where the reconciliation logic resides. Every time a change is detected in
// the Tracee ConfigMap, this function will be called. It will update the Tracee
// DaemonSet, so that the Tracee pods will be restarted with the new configuration.
func (r *ConfigMapReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	return restartDaemonSet(ctx, r.Client, r.TraceeNamespace, r.TraceeName)
}

// SetupWithManager is responsible for connecting the ConfigMapReconciler to the main
// controller manager. It tells the manager that for changes in the Tracee ConfigMap, the
// ConfigMapReconciler should be invoked. It filters to only watch the specific Tracee ConfigMap.
func (r *ConfigMapReconciler) SetupWithManager(mgr ctrl.Manager) error {
	controllerName := "configmap-" + r.ConfigMapName
	return ctrl.NewControllerManagedBy(mgr).
		Named(controllerName).
		For(&corev1.ConfigMap{}).
		WithEventFilter(predicate.NewPredicateFuncs(func(obj client.Object) bool {
			// Only watch the specific Tracee ConfigMap
			return obj.GetNamespace() == r.TraceeNamespace && obj.GetName() == r.ConfigMapName
		})).
		Complete(r)
}
