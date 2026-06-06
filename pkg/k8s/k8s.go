package k8s

import (
	"os"
	"strings"

	"github.com/aquasecurity/tracee/pkg/k8s/apis/tracee.aquasec.com/v1beta1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/rest"
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

func IsMinkube() bool {
	return strings.HasPrefix(os.Getenv("NODE_NAME"), "minikube")
}

func IsKind() bool {
	return strings.HasPrefix(os.Getenv("NODE_NAME"), "kind")
}

// GetListsFilePath returns the default path where lists ConfigMap is mounted
func GetListsFilePath() string {
	return "/etc/tracee/lists.yaml"
}
