package main

import (
	"encoding/gob"
	"flag"
	"io"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/aquasecurity/tracee/pkg/external"
)

func main() {
	var in io.Reader
	file := flag.String("file", "/dev/stdin", "")
	flag.Parse()
	f, err := os.Open(*file)
	if err != nil {
		log.Fatalln("error invalid file: ", *file)
	}
	defer f.Close()
	in = f
	if in == nil {
		log.Fatalln("error invalid input")
	}

	dec := gob.NewDecoder(in)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	log.Println("start")
LOOP:
	for {
		select {
		case <-sig:
			break LOOP
		default:
			var event external.Event
			err = dec.Decode(&event)
			if err != nil {
				if err == io.EOF {
					// ignore EOF becasue we assume events can keep streaming into the file
					time.Sleep(time.Millisecond * 500)
					continue
				} else {
					log.Fatalln(err)
				}
			} else if event.EventName[0] == 4 {
				break LOOP
			}
			log.Println(event)
		}
	}
	log.Println("end")
}
