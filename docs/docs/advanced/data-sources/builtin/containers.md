# Containers Data Source

The [container enrichment](../../../install/container-engines.md) feature gives Tracee the ability to extract details about active containers and link this information to the events it captures.

The [data source](../overview.md) feature makes the information gathered from active containers accessible to signatures. When an event is captured and triggers a signature, that signature can retrieve information about the container using its container ID, which is bundled with the event being analyzed by the signature.

## Internal Data Organization

From the [data-sources documentation](../overview.md), you'll see that searches use keys. It's a bit like looking up information with a specific tag (or a key=value storage).

The `containers data source` operates straightforwardly. Using `string` keys, which represent the container IDs, you can fetch `map[string]string` values as shown below:

```go
    schemaMap := map[string]string{
        "container_id":      "string",
        "container_name":    "string",
        "container_image":   "string",
        "k8s_pod_id":        "string",
        "k8s_pod_name":      "string",
        "k8s_pod_namespace": "string",
        "k8s_pod_sandbox":   "bool",
    }
```

From the structure above, using the container ID lets you access details like the originating Kubernetes pod name or the image utilized by the container.

## Using the Containers Data Source

> Make sure to read [Golang Signatures](../../../events/custom/golang.md) first.

### Signature Initialization

During the signature initialization, get the containers data source instance:

```go
type e2eContainersDataSource struct {
    cb             detect.SignatureHandler
    containersData detect.DataSource
}

func (sig *e2eContainersDataSource) Init(ctx detect.SignatureContext) error {
    sig.cb = ctx.Callback
    containersData, ok := ctx.GetDataSource("tracee", "containers")
    if !ok {
        return fmt.Errorf("containers data source not registered")
    }
    sig.containersData = containersData
    return nil
}
```

Then, to each event being handled, you will `Get()`, from the data source, the information needed.

### On Events

Given the following example:

```go
func (sig *e2eContainersDataSource) OnEvent(event protocol.Event) error {
    eventObj, ok := event.Payload.(trace.Event)
    if !ok {
        return fmt.Errorf("failed to cast event's payload")
    }

    switch eventObj.EventName {
    case "sched_process_exec":
        containerId := eventObj.Container.ID
        if containerId == "" {
            return fmt.Errorf("received non container event")
        }

        container, err := sig.containersData.Get(containerId)
        if !ok {
            return fmt.Errorf("failed to find container in data source: %v", err)
        }

        containerImage, ok := container["container_image"].(string)
        if !ok {
            return fmt.Errorf("failed to obtain the container image name")
        }

        m, _ := sig.GetMetadata()

        sig.cb(detect.Finding{
            SigMetadata: m,
            Event:       event,
            Data:        map[string]interface{}{},
        })
    }

    return nil
}
```

You may see that, through the `event object container ID` information, you may query the data source and obtain the `container name` or any other information listed before.
