package k8s

import (
	"context"

	"github.com/aquasecurity/tracee/pkg/k8s/apis/tracee.aquasec.com/v1beta1"
)

func (c Client) GetDetector(ctx context.Context) ([]v1beta1.DetectorInterface, error) {
	result := v1beta1.DetectorList{}

	err := c.restClient.
		Get().
		Resource("detectors").
		Do(ctx).
		Into(&result)

	if err != nil {
		return nil, err
	}

	detectors := make([]v1beta1.DetectorInterface, len(result.Items))
	for i, item := range result.Items {
		detectors[i] = item
	}

	return detectors, nil
}
