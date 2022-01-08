package main

import (
	"log"
	"os"
	"os/exec"
)

func runCmd(cmdArgs ...string) {
	log.Println("running: ", cmdArgs)
	out, err := exec.Command(cmdArgs[0], cmdArgs[1:]...).Output()
	if err != nil {
		log.Fatalf("command failed: %v, err: %s, msg: %s", cmdArgs, err, string(out))
	}
}

func main() {
	inputArgs := os.Args[1:]
	if len(inputArgs) <= 0 {
		log.Fatal("runner expects one arg of TRC-XX")
	}
	if len(inputArgs) > 1 {
		log.Fatal("invalid args specified: ", inputArgs)
	}

	switch inputArgs[0] {
	case "TRC-3":
		runCmd("./trc3.sh")
	case "TRC-4":
		runCmd("./trc4.sh")
	case "TRC-9":
		runCmd("./trc9.sh")
	case "TRC-10":
		runCmd("./trc10.sh")
	case "TRC-11":
		runCmd("./trc11.sh")
	}
}
