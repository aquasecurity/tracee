package k8s

import (
	"os"
	"strings"
)

func IsMinkube() bool {
	return strings.HasPrefix(os.Getenv("NODE_NAME"), "minikube")
}

func IsKind() bool {
	return strings.HasPrefix(os.Getenv("NODE_NAME"), "kind")
}
