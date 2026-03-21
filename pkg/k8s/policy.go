package k8s

import (
	"context"

	"github.com/aquasecurity/tracee/pkg/k8s/apis/tracee.aquasec.com/v1beta1"
)

func (c Client) GetPolicy(ctx context.Context) ([]v1beta1.PolicyInterface, error) {
	result := v1beta1.PolicyList{}

	err := c.restClient.
		Get().
		Resource("policies").
		Do(ctx).
		Into(&result)

	if err != nil {
		return nil, err
	}

	policies := make([]v1beta1.PolicyInterface, len(result.Items))
	for i, item := range result.Items {
		policies[i] = item
	}

	return policies, nil
}
