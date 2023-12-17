# Writable Data Sources

Since v0.20.0 tracee includes a new `DataSourceService` in its gRPC server. This service includes the ability
to write generic data into a specified data source, both through streaming and unary methods. 
However, in order to utilize this feature, a speciailized `WritableDataSource` must be specified in the RPC arguments.
These data sources are currently only available through custom data sources, meaning that no built-in data sources support this feature.

## How to use

### Implementing a writable data source
Let us implement an example data source which will give us a configurable threshold for reporting some finding.

Start by adding a file `threshold_datasource.go`:
```golang
    package datasourcetest

    import (
        "encoding/json"

        "github.com/aquasecurity/tracee/types/detect"
    )

    type thresholdDataSource struct {
        threshold int
    }

    func (ctx *e2eWritable) Get(key interface{}) (map[string]interface{}, error) {
        keyVal, ok := key.(string)
        if !ok {
            return nil, detect.ErrKeyNotSupported
        }

        if keyVal != "threshold" {
            return nil, detect.ErrKeyNotSupported
        }

        return map[string]interface{}{
            "threshold": ctx.threshold,
        }, nil
    }

    func (ctx *e2eWritable) Version() uint {
        return 1
    }

    func (ctx *e2eWritable) Keys() []string {
        return []string{"string:\"threshold\""}
    }

    func (ctx *e2eWritable) Schema() string {
        schema := map[string]interface{}{
            "threshold": "int",
        }

        s, _ := json.Marshal(schema)
        return string(s)
    }

    func (ctx *e2eWritable) Namespace() string {
        return "my_namespace"
    }

    func (ctx *e2eWritable) ID() string {
        return "threshold_datasource"
    }

    func (ctx *e2eWritable) Write(data map[interface{}]interface{}) error {
        threshold, ok := data["threshold"]
        if !ok {
            return detect.ErrFailedToUnmarshal
        }
        
        // Currently we pass the gRPC values directly, so numbers are sent as float64
        thresholdFloat, ok := threshold.(float64)
        if !ok {
            return detect.ErrFailedToUnmarshal
        }

        ctx.threshold = int(thresholdFloat)
        return nil
    }

    func (ctx *e2eWritable) Values() []string {
        return []string{"string"}
    }
```

!!! Note 
    Unpacking values from the given data dictionary has a specific quirk about value unwrapping.  
    Currently only the gRPC API is given for writing to data sources, which uses the struct.proto package for passing generic values. 
    There is currently no abstraction layer over it, which is why we unpacked the threshold value as float64 in the example, despite wanting 
    it as an int in the end.

### Using in a signature
Now we can use this data source just like we would any other in a signature through the following code:
```golang
    func (sig *mySig) Init(ctx detect.SignatureContext) error {
    ...
    thresholdDataSource, ok := ctx.GetDataSource("my_namespace", "threshold_datasource")
    if !ok {
        return fmt.Errorf("threshold data source not registered")
    }
    if thresholdDataSource.Version() > 1 {
        return fmt.Errorf("threshold data source version not supported, please update this signature")
    }
    sig.thresholdData = thresholdDataSource
    }
```

### Writing to the data source
The following is a short example for a go program which will implement a client for out threshold data source. Note that this is a minimal outline, and you should modify it based on your specific usecase:
```golang
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/aquasecurity/tracee/api/v1beta1"
)

func printAndExit(msg string, args ...any) {
	fmt.Printf(msg, args...)
	os.Exit(1)
}

func main() {
    traceeAddressPtr := flag.String("key", "", "key to set in the data source")
	thresholdPtr := flag.Int("value", "", "key to set in the data source")
	flag.Parse()

	traceeAddress := *traceeAddressPtr
	threshold := *thresholdPtr

	if traceeAddress == "" {
		printAndExit("empty address given\n")
	}
	if threshold == 0 {
		printAndExit("empty threshold given\n")
	}
    if threshold < 0 {
		printAndExit("negative threshold given\n")
	}

	conn, err := grpc.Dial(
		traceeAddress,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		printAndExit("failed to dial tracee grpc server: %v\n", err)
	}
	client := v1beta1.NewDataSourceServiceClient(conn)
	_, err = client.Write(context.Background(), &v1beta1.WriteDataSourceRequest{
		Id:        "my_namespace",
		Namespace: "threshold_datasource",
		Key:       structpb.NewStringValue("threshold"),
		Value:     structpb.NewNumberValue(float64(threshold)),
	})

	if err != nil {
		printAndExit("failed to write to data source: %v\n", err)
	}
}
```

With all these steps completed, you are ready to impelement and use your own writable data source!
