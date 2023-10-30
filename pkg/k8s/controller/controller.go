package controller

import (
	"context"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/aquasecurity/tracee/pkg/k8s/apis/tracee.aquasec.com/v1beta1"
)

// PolicyReconciler reconciles a CronJob object
type PolicyReconciler struct {
	client.Client
	Scheme          *runtime.Scheme
	TraceeNamespace string
	TraceeName      string
}

// +kubebuilder:rbac:groups=tracee.aquasec.com,resources=policies,verbs=get;list;watch;
// +kubebuilder:rbac:groups=apps,resources=daemonsets,verbs=get;list;watch;patch;update;

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.16.0/pkg/reconcile
func (r *PolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var ds appsv1.DaemonSet

	key := client.ObjectKey{
		Namespace: r.TraceeNamespace,
		Name:      r.TraceeName,
	}
	if err := r.Get(ctx, key, &ds); err != nil {
		logger.Error(err, "unable to fetch daemonset")
		return ctrl.Result{}, err
	}

	if ds.Spec.Template.Annotations == nil {
		ds.Spec.Template.Annotations = make(map[string]string)
	}

	// we use the same strategy done by kubect rollout restart,
	// adding a timestamp annotation to the pod template,
	// so that the daemonset controller will rollout a new daemonset
	ds.Spec.Template.Annotations["tracee-operator-restarted"] = time.Now().String()

	if err := r.Update(ctx, &ds); err != nil {
		logger.Error(err, "unable to update daemonset")
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *PolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1beta1.Policy{}).
		Complete(r)
}
