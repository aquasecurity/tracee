package main

import (
	"fmt"

	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type e2eContainersDataSource struct {
	cb             detect.SignatureHandler
	containersData detect.DataSource
}

var e2eContainersDataSourceMetadata = detect.SignatureMetadata{
	ID:          "CONTAINERS_DATA_SOURCE",
	EventName:   "CONTAINERS_DATA_SOURCE",
	Version:     "0.1.0",
	Name:        "Containers Data Source Test",
	Description: "Instrumentation events E2E Tests: Containers Data Source Test",
	Tags:        []string{"e2e", "instrumentation"},
}

func (sig *e2eContainersDataSource) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	containersData, ok := ctx.GetDataSource("tracee", "containers")
	if !ok {
		return fmt.Errorf("containers data source not registered")
	}
	if containersData.Version() > 1 {
		return fmt.Errorf("containers data source version not supported, please update this signature")
	}
	sig.containersData = containersData
	return nil
}

func (sig *e2eContainersDataSource) GetMetadata() (detect.SignatureMetadata, error) {
	return e2eContainersDataSourceMetadata, nil
}

func (sig *e2eContainersDataSource) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "sched_process_exec", Origin: "container"},
	}, nil
}

func (sig *e2eContainersDataSource) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("failed to cast event's payload")
	}

	switch eventObj.EventName {
	case "sched_process_exec":
		pathname, err := helpers.GetTraceeStringArgumentByName(eventObj, "pathname")
		if err != nil {
			return err
		}

		if pathname != "/usr/bin/ls" {
			return nil
		}

		containerId := eventObj.Container.ID
		if containerId == "" {
			return fmt.Errorf("received non container event")
		}

		container, err := sig.containersData.Get(containerId)
		if !ok {
			return fmt.Errorf("failed to find container in data source: %v", err)
		}

		containerIdData, ok := container["container_id"].(string)
		if !ok {
			return fmt.Errorf("failed to extract container id from container data")
		}

		if containerIdData != containerId {
			return fmt.Errorf("container id in data source (%s) did not match query container id (%s)", containerIdData, containerId)
		}

		m, _ := sig.GetMetadata()

		sig.cb(&detect.Finding{
			SigMetadata: m,
			Event:       event,
			Data:        map[string]interface{}{},
		})
	}

	return nil
}

func (sig *e2eContainersDataSource) OnSignal(s detect.Signal) error {
	return nil
}

func (sig *e2eContainersDataSource) Close() {}
