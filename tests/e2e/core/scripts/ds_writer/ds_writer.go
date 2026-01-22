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

// storeName must match detectors/e2e.E2eWritableStoreName (WRITABLE_DATA_STORE e2e test).
const storeName = "writable_store"

func printAndExit(msg string, args ...any) {
	fmt.Printf(msg, args...)
	os.Exit(1)
}

func chooseWord(list []string) string {
	return list[rand.Intn(len(list))]
}

func writeData(ctx context.Context, conn grpc.ClientConnInterface, key, value string) error {
	keyAny, err := anypb.New(structpb.NewStringValue(key))
	if err != nil {
		return err
	}
	dataAny, err := anypb.New(structpb.NewStringValue(value))
	if err != nil {
		return err
	}
	client := datastores.NewDataStoreServiceClient(conn)
	_, err = client.WriteData(ctx, &datastores.WriteDataRequest{
		StoreName: storeName,
		Source:    "grpc",
		Entry:     &datastores.DataEntry{Key: keyAny, Data: dataAny},
	})
	return err
}

func writeBatchData(ctx context.Context, conn grpc.ClientConnInterface, entries []struct{ Key, Value string }) error {
	if len(entries) == 0 {
		return nil
	}
	protoEntries := make([]*datastores.DataEntry, 0, len(entries))
	for _, e := range entries {
		keyAny, err := anypb.New(structpb.NewStringValue(e.Key))
		if err != nil {
			return err
		}
		dataAny, err := anypb.New(structpb.NewStringValue(e.Value))
		if err != nil {
			return err
		}
		protoEntries = append(protoEntries, &datastores.DataEntry{Key: keyAny, Data: dataAny})
	}
	client := datastores.NewDataStoreServiceClient(conn)
	_, err := client.WriteBatchData(ctx, &datastores.WriteBatchDataRequest{
		StoreName: storeName,
		Source:    "grpc",
		Entries:   protoEntries,
	})
	return err
}

func contaminate(ctx context.Context, conn *grpc.ClientConn) error {
	entries := make([]struct{ Key, Value string }, 1000)
	for i := 0; i < 1000; i++ {
		entries[i] = struct{ Key, Value string }{
			Key:   chooseWord(wordList),
			Value: chooseWord(wordList),
		}
	}
	return writeBatchData(ctx, conn, entries)
}

func main() {
	keyPtr := flag.String("key", "", "key to set in the writable store")
	valuePtr := flag.String("value", "", "value to set in the writable store")
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

	if err := contaminate(ctx, conn); err != nil {
		printAndExit("error contaminating writable store: %v\n", err)
	}
	if err := writeData(ctx, conn, key, value); err != nil {
		printAndExit("failed to write to writable store: %v\n", err)
	}
}
