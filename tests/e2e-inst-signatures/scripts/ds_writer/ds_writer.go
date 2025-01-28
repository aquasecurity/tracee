package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/aquasecurity/tracee/api/v1beta1"
)

func printAndExit(msg string, args ...any) {
	fmt.Printf(msg, args...)
	os.Exit(1)
}

func chooseWord(list []string) string {
	return list[rand.Intn(len(list))]
}

func contaminate(ctx context.Context, client v1beta1.DataSourceServiceClient) error {
	stream, err := client.WriteStream(ctx)
	if err != nil {
		return fmt.Errorf("error establishing stream: %v", err)
	}
	for i := 0; i < 1000; i++ {
		randomKey := chooseWord(wordList)
		randomValue := chooseWord(wordList)
		err := stream.Send(&v1beta1.WriteDataSourceRequest{
			Id:        "demo",
			Namespace: "e2e_inst",
			Key:       structpb.NewStringValue(randomKey),
			Value:     structpb.NewStringValue(randomValue),
		})
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}

			return err
		}
	}
	_, err = stream.CloseAndRecv()
	if err != nil {
		return fmt.Errorf("error closing stream: %v", err)
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

	client := v1beta1.NewDataSourceServiceClient(conn)
	err = contaminate(ctx, client)
	if err != nil {
		printAndExit("error contaminating data source: %v\n", err)
	}
	_, err = client.Write(ctx, &v1beta1.WriteDataSourceRequest{
		Id:        "demo",
		Namespace: "e2e_inst",
		Key:       structpb.NewStringValue(key),
		Value:     structpb.NewStringValue(value),
	})

	if err != nil {
		printAndExit("failed to write to data source: %v\n", err)
	}
}
