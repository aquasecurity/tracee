package main

import (
	"fmt"
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

func runCmdInBackground(cmdArgs ...string) *exec.Cmd {
	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	err := cmd.Start()
	if err != nil {
		log.Fatalf(" background command failed: %v, err: %s", cmdArgs, err)
	}
	return cmd
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
		cmd := runCmdInBackground("nc", "-l", "4444")
		runCmd("sleep", "1")
		runCmd("./injector", "load.so", fmt.Sprintf("%d", cmd.Process.Pid))
		if err := cmd.Wait(); err != nil {
			log.Fatal(err)
		}
	case "TRC-4":
		runCmd("cp", "/bin/ls", "/tmp/packed_ls")
		runCmd("upx", "/tmp/packed_ls")
		runCmd("/tmp/packed_ls")
	case "TRC-9":
		runCmd("cp", "load.so", "load1.so")
	case "TRC-10":
		runCmd("cat", "/etc/kubernetes/pki/token")
	case "TRC-11":
		runCmd("mkdir", "-p", "/mnt/foo")
		runCmd("mount", "/dev/sda1", "/mnt/foo")
	}
}
