package main

import (
	"context"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/aquasecurity/tracee/api/v1beta1/datastores"
)

func printAndExit(msg string, args ...any) {
	fmt.Printf(msg, args...)
	os.Exit(1)
}

func chooseWord(list []string) string {
	return list[rand.Intn(len(list))]
}

func contaminate(ctx context.Context, client datastores.DataStoreServiceClient) error {
	// Collect all entries for batch write
	entries := make([]*datastores.DataEntry, 0, 1000)

	for i := 0; i < 1000; i++ {
		randomKey := chooseWord(wordList)
		randomValue := chooseWord(wordList)

		// Convert strings to anypb.Any
		keyAny, err := anypb.New(structpb.NewStringValue(randomKey))
		if err != nil {
			return fmt.Errorf("failed to create key anypb: %v", err)
		}

		valueAny, err := anypb.New(structpb.NewStringValue(randomValue))
		if err != nil {
			return fmt.Errorf("failed to create value anypb: %v", err)
		}

		entries = append(entries, &datastores.DataEntry{
			Key:  keyAny,
			Data: valueAny,
		})
	}

	// Write all entries in a batch
	_, err := client.WriteBatchData(ctx, &datastores.WriteBatchDataRequest{
		StoreName: "demo",     // Store name matches the datasource ID
		Source:    "e2e_inst", // Source matches the namespace
		Entries:   entries,
	})
	if err != nil {
		return fmt.Errorf("error writing batch data: %v", err)
	}

	return nil
}

func main() {
	keyPtr := flag.String("key", "", "key to set in the data source")
	valuePtr := flag.String("value", "", "key to set in the data source")
	flag.Parse()

	key := *keyPtr
	value := *valuePtr

	if key == "" {
		printAndExit("empty key given\n")
	}
	if value == "" {
		printAndExit("empty value given\n")
	}

	conn, err := grpc.NewClient(
		"unix:///tmp/tracee.sock",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		printAndExit("failed to dial tracee grpc server: %v\n", err)
	}
	defer func() {
		err := conn.Close()
		if err != nil {
			printAndExit("failed to close connection: %v\n", err)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()

	client := datastores.NewDataStoreServiceClient(conn)
	err = contaminate(ctx, client)
	if err != nil {
		printAndExit("error contaminating data source: %v\n", err)
	}

	// Write the final key-value pair
	keyAny, err := anypb.New(structpb.NewStringValue(key))
	if err != nil {
		printAndExit("failed to create key anypb: %v\n", err)
	}

	valueAny, err := anypb.New(structpb.NewStringValue(value))
	if err != nil {
		printAndExit("failed to create value anypb: %v\n", err)
	}

	_, err = client.WriteData(ctx, &datastores.WriteDataRequest{
		StoreName: "demo",     // Store name matches the datasource ID
		Source:    "e2e_inst", // Source matches the namespace
		Entry: &datastores.DataEntry{
			Key:  keyAny,
			Data: valueAny,
		},
	})

	if err != nil {
		printAndExit("failed to write to data source: %v\n", err)
	}
}
