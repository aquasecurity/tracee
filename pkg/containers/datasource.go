package containers

import (
	"encoding/json"

	"github.com/aquasecurity/tracee/types/detect"
)

type SignaturesDataSource struct {
	containers *Containers
}

func NewDataSource(c *Containers) *SignaturesDataSource {
	return &SignaturesDataSource{
		containers: c,
	}
}

func (ctx SignaturesDataSource) Get(key interface{}) (map[string]interface{}, error) {
	containerId, ok := key.(string)
	if !ok {
		return nil, detect.ErrKeyNotSupported
	}
	ctx.containers.mtx.RLock()
	defer ctx.containers.mtx.RUnlock()
	for _, cgroup := range ctx.containers.cgroupsMap {
		if cgroup.Container.ContainerId == containerId {
			containerData := cgroup.Container
			podData := containerData.Pod
			result := make(map[string]interface{}, 7)
			result["container_id"] = containerData.ContainerId
			result["container_name"] = containerData.Name
			result["container_image"] = containerData.Image
			result["k8s_pod_id"] = podData.UID
			result["k8s_pod_name"] = podData.Name
			result["k8s_pod_namespace"] = podData.Namespace
			result["k8s_pod_sandbox"] = podData.Sandbox
			return result, nil
		}
	}
	return nil, detect.ErrDataNotFound
}

func (ctx SignaturesDataSource) Keys() []string {
	return []string{"string"}
}

func (ctx SignaturesDataSource) Schema() string {
	schemaMap := map[string]string{
		"container_id":      "string",
		"container_name":    "string",
		"container_image":   "string",
		"k8s_pod_id":        "string",
		"k8s_pod_name":      "string",
		"k8s_pod_namespace": "string",
		"k8s_pod_sandbox":   "bool",
	}
	schema, _ := json.Marshal(schemaMap)
	return string(schema)
}

func (ctx SignaturesDataSource) Version() uint {
	return 1
}

func (ctx SignaturesDataSource) Namespace() string {
	return "tracee"
}

func (ctx SignaturesDataSource) ID() string {
	return "containers"
}
