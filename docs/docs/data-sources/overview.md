# Data Sources (Experimental)

Data sources are a new feature, which will be the base of allowing access to dynamic data stores in signature writing (currently only available in golang).  
Data sources are currently an experimental feature and in active development, and usage is opt-in.

## Why use data sources?

Data sources should be used when a signature requires access to data not available to it from the events it receives.  
For example, a signature may need access to additional data about a container where an event was generated. Using tracee's builtin container data source it can do so without additionally tracking container lifecycle events.

## What data sources can I use

Currently, only builtin data sources from tracee are available.  
Initially only a data source for containers will be available, but the list will be expanded as this and other features are further developed.  

## How to use data sources
In order to use a data source in a signature you must request access to it in the `Init` stage. This can be done through the `SignatureContext` passed at that stage as such:
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

As you can see we have requested access to the data source through two keys, a namespace, and a data source ID. Namespaces are used to avoid name conflicts in the future when custom data sources can be integrated. All of tracee's builtin data sources will be available under the "tracee" namespace.  
After checking the data source is available, we suggest to add a version check against the data source. Doing so will let you avoid running a signature which was not updated to run with a new data source schema.  

Now, in the `OnEvent` function, you may use the data source like so:  
```golang
container, err := sig.containersData.Get(containerId)
if !ok {
    return fmt.Errorf("failed to find container in data source: %v", err)
}

containerName := container["container_name"].(string)
``` 
Each Data source comes with one querying method `Get(key any) map[string]any`. In the above example, omitting the type validation when checking the key, which was safe to do by following the schema (given through the `Schema()` method), a json representation of the returned map, and initially checking the data source version.