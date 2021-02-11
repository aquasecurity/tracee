package main

import (
	"fmt"
	"github.com/aquasecurity/tracee/tracee-rules/types"
	tracee "github.com/aquasecurity/tracee/tracee/external"
)

type stdioOverSocket struct {
	cb              types.SignatureHandler
	processSocketIp map[int]map[int]string
}

func (sig *stdioOverSocket) Init(cb types.SignatureHandler) error {
	sig.cb = cb
	sig.processSocketIp = make(map[int]map[int]string)

	return nil
}

func (sig *stdioOverSocket) GetMetadata() (types.SignatureMetadata, error) {
	return types.SignatureMetadata{
		Name:        "Standard Input/Output Over Socket",
		Description: "Redirection of process's standard input/output to socket",
		Tags:        []string{"linux", "container"},
		Properties: map[string]interface{}{
			"Severity":     3,
			"MITRE ATT&CK": "Persistence: Server Software Component",
		},
	}, nil
}

func (sig *stdioOverSocket) GetSelectedEvents() ([]types.SignatureEventSelector, error) {
	return []types.SignatureEventSelector{
		{Source: "tracee", Name: "connect"},
		{Source: "tracee", Name: "dup2"},
		{Source: "tracee", Name: "dup3"},
		{Source: "tracee", Name: "close"},
		{Source: "tracee", Name: "sched_process_exit"},
	}, nil
}

func (sig *stdioOverSocket) OnEvent(e types.Event) error {

	eventObj, ok := e.(tracee.Event)
	if !ok {
		return fmt.Errorf("invalid event")
	}

	var connectData connectAddrData
	stdAll := []int{0, 1, 2}

	pid := eventObj.ProcessID

	switch eventObj.EventName {

	case "connect":

		sockfdArg, err := GetTraceeArgumentByName(eventObj, "sockfd")
		if err != nil {
			return err
		}

		sockfd := sockfdArg.Value.(int)

		addrArg, err := GetTraceeArgumentByName(eventObj, "addr")
		if err != nil {
			return err
		}

		err = GetAddrStructFromArg(addrArg, &connectData)
		if err != nil {
			return err
		}

		if connectData.SaFamily == "AF_INET" {

			_, pidExists := sig.processSocketIp[pid]

			if !pidExists {
				sig.processSocketIp[pid] = make(map[int]string)
			}

			sig.processSocketIp[pid][sockfd] = connectData.SinAddr
		}

	case "dup2", "dup3":

		_, pidExists := sig.processSocketIp[pid]

		if !pidExists {
			return nil
		}

		oldFdArg, err := GetTraceeArgumentByName(eventObj, "oldfd")
		if err != nil {
			return err
		}

		srcFd := oldFdArg.Value.(int)

		newFdArg, err := GetTraceeArgumentByName(eventObj, "newfd")
		if err != nil {
			return err
		}

		dstFd := newFdArg.Value.(int)

		ip, socketfdExists := sig.processSocketIp[pid][srcFd]

		// this means that a socket FD is duplicated into one of the standard FDs
		if socketfdExists && intInSlice(dstFd, stdAll) && !intInSlice(srcFd, stdAll) {
			sig.cb(types.Finding{
				Signature: sig,
				Context:   eventObj,
				Data: map[string]interface{}{
					"ip": ip,
				},
			})
		}

	case "close":

		currentFdArg, err := GetTraceeArgumentByName(eventObj, "fd")
		if err != nil {
			return err
		}

		currentFd := currentFdArg.Value.(int)

		delete(sig.processSocketIp[pid], currentFd)

	case "sched_process_exit":

		delete(sig.processSocketIp, pid)

	}

	return nil
}

func (sig *stdioOverSocket) OnSignal(s types.Signal) error {
	return nil
}

func intInSlice(a int, list []int) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}
