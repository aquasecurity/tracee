package main

import (
	"encoding/json"
	"fmt"
	"log"

	v1beta1 "github.com/aquasecurity/tracee/types/api/v1beta1"
)

type CloudContext struct {
	Provider string
}

type Context_Cloud struct {
	Cloud                   *CloudContext
	v1beta1.IContextContext `json:"-"`
}

func main() {
	e := v1beta1.Event{
		Id:   123,
		Name: "ptrace",
	}

	e.SetProcessContext(&v1beta1.ProcessContext{
		Binary:       "/bin/bash",
		Pid:          10,
		NamespacePid: 1,
		UserId:       1,
		UserName:     "root",
	})
	// process := e.GetProcessContext()

	e.SetContainerContext(&v1beta1.ContainerContext{
		Id:      "lala",
		Name:    "xx",
		Started: true,
	})
	// container := e.GetContainerContext()

	e.SetKubernetesContext(&v1beta1.KubernetesContext{
		Name:      "pod-name",
		Namespace: "prod",
		Uid:       "uid",
		Sandbox:   "sandbox",
	})
	// kubernetes := e.GetKubernetesContext()

	// fmt.Printf("process: %+v\n", process)
	// fmt.Printf("container: %+v\n", container)
	// fmt.Printf("kubernetes: %+v\n", kubernetes)

	cloud := CloudContext{Provider: "gcloud"}
	// fmt.Printf("cloud: %+v\n\n", cloud)
	// fmt.Printf("before len: %d\n", len(e.Context))
	e.Context = append(e.Context, &v1beta1.Context{Context: &Context_Cloud{Cloud: &cloud}})
	// fmt.Printf("after len: %d\n", len(e.Context))

	// fmt.Printf("event: %+v\n", e)

	b, err := json.Marshal(e)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(b))
}
