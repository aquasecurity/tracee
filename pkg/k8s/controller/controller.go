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
// DaemonSet, so that the Tracee pods will be restarted with the new policy. It does this
// by adding a timestamp annotation to the pod template, so that the daemonset controller
// will rollout a new daemonset ("restarting" the daemonset).
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

// SetupWithManager is responsible for connecting the PolicyReconciler to the main
// controller manager. It tells the manager that for changes in v1beta1Policy objects, the
// PolicyReconciler should be invoked.
func (r *PolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1beta1.Policy{}).
		Complete(r)
}
