package main

import (
	"encoding/gob"
	"flag"
	"io"
	"log"
	"os"
	"os/signal"
	"time"
)

// Event is a user facing data structure representing a single event
type Event struct {
	Timestamp           float64    `json:"timestamp"`
	ProcessID           int        `json:"processId"`
	ThreadID            int        `json:"threadId"`
	ParentProcessID     int        `json:"parentProcessId"`
	HostProcessID       int        `json:"hostProcessId"`
	HostThreadID        int        `json:"hostThreadId"`
	HostParentProcessID int        `json:"hostParentProcessId"`
	UserID              int        `json:"userId"`
	MountNS             int        `json:"mountNamespace"`
	PIDNS               int        `json:"pidNamespace"`
	ProcessName         string     `json:"processName"`
	HostName            string     `json:"hostName"`
	EventID             int        `json:"eventId,string"`
	EventName           string     `json:"eventName"`
	ArgsNum             int        `json:"argsNum"`
	ReturnValue         int        `json:"returnValue"`
	Args                []Argument `json:"args"` //Arguments are ordered according their appearance in the original event
}

// Argument holds the information for one argument
type Argument struct {
	Name  string      `json:"name"`
	Value interface{} `json:"value"`
}

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
			var event Event
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
