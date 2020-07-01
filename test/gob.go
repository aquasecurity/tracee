package main

import (
	"encoding/gob"
	"flag"
	"io"
	"log"
	"os"
	"os/signal"
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
			var ctx context
			var args []interface{}

			err = dec.Decode(&ctx)
			if err != nil {
				if err == io.EOF {
					break LOOP
				} else {
					log.Fatalln(err)
				}
			}
			err = dec.Decode(&args)
			if err != nil {
				if err == io.EOF {
					break LOOP
				} else {
					log.Fatalln(err)
				}
			}
			log.Println("event:")
			log.Println(ctx)
			log.Println(args)
		}
	}
	log.Println("end")
}

// the following types are copy-pasted from tracee.go
type taskComm [16]byte

func (tc taskComm) String() string {
	len := 0
	for i, b := range tc {
		if b == 0 {
			len = i
			break
		}
	}
	return string(tc[:len])
}

func (tc taskComm) MarshalText() ([]byte, error) {
	return []byte(tc.String()), nil
}

type context struct {
	Ts      uint64   `json:"time"`
	Pid     uint32   `json:"pid"`
	Tid     uint32   `json:"tid"`
	Ppid    uint32   `json:"ppid"`
	Uid     uint32   `json:"uid"`
	MntId   uint32   `json:"mnt_ns"`
	PidId   uint32   `json:"pid_ns"`
	Comm    taskComm `json:"process_name"`
	UtsName taskComm `json:"uts_name"`
	Eventid int32    `json:"api"`
	Argnum  uint8    `json:"arguments_count"`
	_       [3]byte  // padding for Argnum
	Retval  int64    `json:"return_value"`
}
