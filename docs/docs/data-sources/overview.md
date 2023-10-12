# Data Sources (Experimental)

Data sources are a new feature, which will be the base of allowing access to
dynamic data stores in signature writing (currently only available in golang).

> Data sources are currently an experimental feature and in active development,
> and usage is opt-in.

## Why use data sources?

Signatures should opt for data sources when they need access to data beyond what
is provided by the events they process.

For instance, a signature may need access to data about the container where the
event being processed was generated. With Tracee's integrated container data
source, this can be achieved without the signature having to separately monitor
container lifecycle events.

## What data sources can I use

For now, only the built-in data sources from Tracee are at your disposal.
Looking ahead, there are plans to enable integration of data sources into Tracee
either as plugins or extensions.

Currently, two primary data source exist:

1. Containers: Provides metadata about containers given a container id.
1. Process Tree: Provides access to a tree of ever existing processes and threads.

This list will be expanded as other features are developed.

## How to use data sources

In order to use a data source in a signature you must request access to it in
the `Init` stage. This can be done through the `SignatureContext` passed at that
stage as such:

```golang
func (sig *mySig) Init(ctx detect.SignatureContext) error {
    ...
    containersData, ok := ctx.GetDataSource("tracee", "containers")
 if !ok {
  return fmt.Errorf("containers data source not registered")
 }
    if containersData.Version() > 1 {
  return fmt.Errorf("containers data source version not supported, please update this signature")
 }
 sig.containersData = containersData
}
```

As you can see, access to the data source has been requested using two keys: a
namespace and a data source ID. Namespaces are employed to prevent name
conflicts in the future when integrating custom data sources. All built-in data
sources from Tracee will be available under the "tracee" namespace.

After verifying the data source's availability, it's suggested to include a
version check against the data source. This approach ensures that outdated
signatures aren't run with a newer data source schema.

Now, in the `OnEvent` function, you may use the data source like so:

```golang
container, err := sig.containersData.Get(containerId)
if !ok {
    return fmt.Errorf("failed to find container in data source: %v", err)
}

containerName := container["container_name"].(string)
```

Each Data source provides a querying method `Get(key any) map[string]any`. In
the provided example, type validation is omitted during key verification. This
omission is safe when adhering to the schema (provided by the `Schema()`
method), considering the JSON representation of the returned map, and after an
initial check of the data source version.
