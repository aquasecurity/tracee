package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/api"
	promv1 "github.com/prometheus/client_golang/api/prometheus/v1"
	"github.com/urfave/cli/v2"
)

const (
	prometheusAddressFlag = "prometheus"
	periodFlag            = "period"
	outputFlag            = "output"
)

type measurement struct {
	AvgEbpfRate       float64 `json:"avgEbpfRate"`
	AvgLostEventsRate float64 `json:"avgLostEventsRate"`
	LostEvents        int     `json:"lostEvents"`
}

func (m measurement) Print() {
	log.Printf("\n")
	fmt.Printf("Events/Sec:     %f\n", m.AvgEbpfRate)
	fmt.Printf("EventsLost/Sec: %f\n", m.AvgLostEventsRate)
	fmt.Printf("Events Lost:    %d\n", m.LostEvents)
	fmt.Println("===============================================")
}
func (m measurement) PrintJson() {
	res, _ := json.Marshal(m)
	fmt.Println(string(res))
}

type OutputMode string

const (
	jsonOutput   OutputMode = "json"
	prettyOutput OutputMode = "pretty"
)

func main() {
	app := cli.App{
		Name:  "tracee-bench",
		Usage: "A prometheus based performance probe for tracee",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  prometheusAddressFlag,
				Usage: "address of a prometheus instance tracking tracee",
				Value: "http://localhost:9090",
			},
			&cli.IntFlag{
				Name:  periodFlag,
				Usage: "period of scraping in seconds",
				Value: 5,
			},
			&cli.StringFlag{
				Name:  outputFlag,
				Usage: "set output format (options: pretty, json)",
				Value: "pretty",
			},
		},
		Action: func(ctx *cli.Context) error {
			address := ctx.String(prometheusAddressFlag)

			if address == "" {
				return fmt.Errorf("prometheus address required for tracee-er")
			}

			client, err := api.NewClient(api.Config{
				Address: address,
			})

			if err != nil {
				return err
			}

			done := sigHandler()
			prom := promv1.NewAPI(client)
			ticker := time.NewTicker(time.Duration(ctx.Int(periodFlag)) * time.Second)

			// promql queries
			const (
				eventspersec = "events/sec"
				lostpersec   = "lost/sec"
				rulespersec  = "rules/sec"
				lostoverall  = "lost_events"
			)
			queries := map[string]struct {
				queryName string
				query     string
			}{
				eventspersec: {queryName: "average ebpf_events/sec", query: "rate(tracee_ebpf_events_total[1m])"},
				lostpersec:   {queryName: "average ebpf_lostevents/sec", query: "rate(tracee_ebpf_lostevents_total[1m])"},
				lostoverall:  {queryName: "lost events", query: "tracee_ebpf_lostevents_total"},
			}

			outputMode := OutputMode(ctx.String(outputFlag))
			if outputMode == prettyOutput {
				fmt.Println("===================TRACEE-ER===================")
			}
			go func() {
				for {
					select {
					case <-done:
						{
							return
						}
					case now := <-ticker.C:
						{
							measurement := measurement{}
							wg := sync.WaitGroup{}
							wg.Add((len(queries)))
							for field, query := range queries {
								go func(queryField string, queryName string, query string) {
									defer wg.Done()
									res, _, err := prom.Query(context.Background(), query, now)
									if err != nil {
										log.Printf("failed to fetch %s: %v\n", queryName, err)
										return
									}

									queryResString := res.String()
									if queryResString == "" {
										log.Printf("failed to fetch %s: empty\n", queryName)
										return
									}
									val, _ := parseQueryResString(queryResString)
									switch queryField {
									case eventspersec:
										measurement.AvgEbpfRate = val
									case lostpersec:
										measurement.AvgLostEventsRate = val
									case lostoverall:
										measurement.LostEvents = int(val)
									}
								}(field, query.queryName, query.query)
							}
							wg.Wait()
							switch outputMode {
							case prettyOutput:
								measurement.Print()
							case jsonOutput:
								measurement.PrintJson()
							}
						}
					}
				}
			}()
			<-done
			return nil
		},
	}
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func parseQueryResString(queryRes string) (float64, error) {
	startIndex := strings.LastIndex(queryRes, "=> ") + 3
	lastIndex := strings.LastIndex(queryRes, "@[") - 1
	return strconv.ParseFloat(queryRes[startIndex:lastIndex], 64)
}

func sigHandler() chan bool {
	sigs := make(chan os.Signal, 1)
	done := make(chan bool, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		done <- true
	}()
	return done
}
