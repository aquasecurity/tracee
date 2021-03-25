package main

import (
	"fmt"

	tracee "github.com/aquasecurity/tracee/tracee-ebpf/tracee/external"
	"github.com/aquasecurity/tracee/tracee-rules/signatures/helpers"
	"github.com/aquasecurity/tracee/tracee-rules/types"
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
		ID:          "TRC-1",
		Version:     "0.1.0",
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
		{Source: "tracee", Name: "dup"},
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

	var connectData helpers.ConnectAddrData

	pid := eventObj.ProcessID

	switch eventObj.EventName {

	case "connect":

		sockfdArg, err := helpers.GetTraceeArgumentByName(eventObj, "sockfd")
		if err != nil {
			return err
		}

		sockfd := int(sockfdArg.Value.(int32))

		addrArg, err := helpers.GetTraceeArgumentByName(eventObj, "addr")
		if err != nil {
			return err
		}

		err = helpers.GetAddrStructFromArg(addrArg, &connectData)
		if err != nil {
			return err
		}

		if connectData.SaFamily == "AF_INET" {

			_, pidExists := sig.processSocketIp[pid]
			if !pidExists {
				sig.processSocketIp[pid] = make(map[int]string)
			}

			sig.processSocketIp[pid][sockfd] = connectData.SinAddr

		} else if connectData.SaFamily == "AF_INET6" {

			_, pidExists := sig.processSocketIp[pid]
			if !pidExists {
				sig.processSocketIp[pid] = make(map[int]string)
			}

			sig.processSocketIp[pid][sockfd] = connectData.SinAddr6
		}

	case "dup":

		pidSocketMap, pidExists := sig.processSocketIp[pid]

		if !pidExists {
			return nil
		}

		oldFdArg, err := helpers.GetTraceeArgumentByName(eventObj, "oldfd")
		if err != nil {
			return err
		}

		srcFd := int(oldFdArg.Value.(int32))

		dstFd := eventObj.ReturnValue

		err = isStdioOverSocket(sig, eventObj, pidSocketMap, srcFd, dstFd)
		if err != nil {
			return err
		}

	case "dup2", "dup3":

		pidSocketMap, pidExists := sig.processSocketIp[pid]

		if !pidExists {
			return nil
		}

		oldFdArg, err := helpers.GetTraceeArgumentByName(eventObj, "oldfd")
		if err != nil {
			return err
		}

		srcFd := int(oldFdArg.Value.(int32))

		newFdArg, err := helpers.GetTraceeArgumentByName(eventObj, "newfd")
		if err != nil {
			return err
		}

		dstFd := int(newFdArg.Value.(int32))

		err = isStdioOverSocket(sig, eventObj, pidSocketMap, srcFd, dstFd)
		if err != nil {
			return err
		}

	case "close":

		currentFdArg, err := helpers.GetTraceeArgumentByName(eventObj, "fd")
		if err != nil {
			return err
		}

		currentFd := int(currentFdArg.Value.(int32))

		delete(sig.processSocketIp[pid], currentFd)

	case "sched_process_exit":

		delete(sig.processSocketIp, pid)

	}

	return nil
}

func (sig *stdioOverSocket) OnSignal(s types.Signal) error {
	return nil
}

func isStdioOverSocket(sig *stdioOverSocket, eventObj tracee.Event, pidSocketMap map[int]string, srcFd int, dstFd int) error {
	stdAll := []int{0, 1, 2}
	ip, socketfdExists := pidSocketMap[srcFd]

	// this means that a socket FD is duplicated into one of the standard FDs
	if socketfdExists && intInSlice(dstFd, stdAll) {
		m, _ := sig.GetMetadata()
		sig.cb(types.Finding{
			SigMetadata: m,
			Context:     eventObj,
			Data: map[string]interface{}{
				"ip": ip,
			},
		})
	}

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
