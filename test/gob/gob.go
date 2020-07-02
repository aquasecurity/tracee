package main

import (
	"encoding/gob"
	"flag"
	"io"
	"log"
	"os"
	"os/signal"

	"github.com/aquasecurity/tracee/tracee"
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
	sig := make(chan os.Signal)
	signal.Notify(sig, os.Interrupt)
	log.Println("start")
LOOP:
	for {
		select {
		case <-sig:
			break LOOP
		default:
			var event tracee.Event

			err = dec.Decode(&event)
			if err != nil {
				if err == io.EOF {
					break LOOP
				} else {
					log.Fatalln(err)
				}
			}
			log.Println("event:")
			log.Println(event)
		}
	}
	log.Println("end")
}
