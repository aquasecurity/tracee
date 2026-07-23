// +kubebuilder:object:generate=true
// +groupName=tracee.aquasec.com
package v1beta1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	// GroupVersion is group version used to register these objects
	GroupVersion = schema.GroupVersion{Group: "tracee.aquasec.com", Version: "v1beta1"}

	// SchemeBuilder is used to add go types to the GroupVersionKind scheme.
	// Uses apimachinery's runtime.SchemeBuilder directly (rather than
	// controller-runtime's deprecated pkg/scheme.Builder) to keep this api
	// package free of a controller-runtime dependency.
	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)

	// AddToScheme adds the types in this group-version to the given scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)

// addKnownTypes registers the group's types and the GroupVersion's metav1
// helper types with the scheme.
func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(GroupVersion, &Policy{}, &PolicyList{})
	metav1.AddToGroupVersion(scheme, GroupVersion)
	return nil
}
