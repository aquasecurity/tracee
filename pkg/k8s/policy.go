package k8s

import (
	"context"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/rest"

	"github.com/aquasecurity/tracee/pkg/k8s/apis/tracee.aquasec.com/v1beta1"
)

type Client struct {
	restClient *rest.RESTClient
}

func New() (*Client, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}

	scheme := runtime.NewScheme()
	err = v1beta1.AddToScheme(scheme)
	if err != nil {
		return nil, err
	}

	crdConfig := *config
	crdConfig.ContentConfig.GroupVersion = &v1beta1.GroupVersion
	crdConfig.APIPath = "/apis"
	crdConfig.NegotiatedSerializer = serializer.NewCodecFactory(scheme)
	crdConfig.UserAgent = rest.DefaultKubernetesUserAgent()

	client, err := rest.UnversionedRESTClientFor(&crdConfig)
	if err != nil {
		return nil, err
	}

	return &Client{client}, nil
}

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
