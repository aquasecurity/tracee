package main

import (
	"fmt"

	tracee "github.com/aquasecurity/tracee/pkg/external"
	"github.com/aquasecurity/tracee/tracee-rules/signatures/helpers"
	"github.com/aquasecurity/tracee/tracee-rules/types"
)

type connectedAddress struct {
	ip   string
	port string
}

type stdioOverSocket struct {
	cb              types.SignatureHandler
	pidFDAddressMap map[int]map[int]connectedAddress
}

func (sig *stdioOverSocket) Init(cb types.SignatureHandler) error {
	sig.cb = cb
	sig.pidFDAddressMap = make(map[int]map[int]connectedAddress)

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
		{Source: "tracee", Name: "security_socket_connect"},
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

	pid := eventObj.ProcessID

	switch eventObj.EventName {

	case "security_socket_connect":

		remoteAddrArg, err := helpers.GetTraceeArgumentByName(eventObj, "remote_addr")
		if err != nil {
			return err
		}

		var address connectedAddress
		address, err = getAddressfromAddrArg(remoteAddrArg)
		if err != nil {
			return err
		}

		sockfdArg, err := helpers.GetTraceeArgumentByName(eventObj, "sockfd")
		if err != nil {
			return err
		}

		sockfd := int(sockfdArg.Value.(int32))

		err = isSocketOverStdio(sig, eventObj, address, sockfd)
		if err != nil {
			return err
		}

		_, pidExists := sig.pidFDAddressMap[pid]
		if !pidExists {
			sig.pidFDAddressMap[pid] = make(map[int]connectedAddress)
		}

		if address.ip != "" && address.port != "" {
			sig.pidFDAddressMap[pid][sockfd] = address
		}

	case "dup":

		pidSocketMap, pidExists := sig.pidFDAddressMap[pid]

		if !pidExists {
			return nil
		}

		oldFdArg, err := helpers.GetTraceeArgumentByName(eventObj, "oldfd")
		if err != nil {
			return err
		}

		srcFd := int(oldFdArg.Value.(int32))

		dstFd := eventObj.ReturnValue

		err = isSocketDuplicatedIntoStdio(sig, eventObj, pidSocketMap, srcFd, dstFd)
		if err != nil {
			return err
		}

	case "dup2", "dup3":

		pidSocketMap, pidExists := sig.pidFDAddressMap[pid]

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

		err = isSocketDuplicatedIntoStdio(sig, eventObj, pidSocketMap, srcFd, dstFd)
		if err != nil {
			return err
		}

	case "close":

		currentFdArg, err := helpers.GetTraceeArgumentByName(eventObj, "fd")
		if err != nil {
			return err
		}

		currentFd := int(currentFdArg.Value.(int32))

		delete(sig.pidFDAddressMap[pid], currentFd)

	case "sched_process_exit":

		delete(sig.pidFDAddressMap, pid)

	}

	return nil
}

func (sig *stdioOverSocket) OnSignal(s types.Signal) error {
	return nil
}
func (sig *stdioOverSocket) Close() {}

func isSocketDuplicatedIntoStdio(sig *stdioOverSocket, eventObj tracee.Event, pidSocketMap map[int]connectedAddress, srcFd int, dstFd int) error {
	address, socketfdExists := pidSocketMap[srcFd]

	// this means that a socket FD is duplicated into one of the standard FDs
	if socketfdExists {
		isSocketOverStdio(sig, eventObj, address, dstFd)
	}

	return nil
}

func isSocketOverStdio(sig *stdioOverSocket, eventObj tracee.Event, address connectedAddress, fd int) error {

	stdAll := []int{0, 1, 2}

	if intInSlice(fd, stdAll) {
		m, _ := sig.GetMetadata()
		sig.cb(types.Finding{
			SigMetadata: m,
			Context:     eventObj,
			Data: map[string]interface{}{
				"ip":   address.ip,
				"port": address.port,
				"fd":   fd,
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

func getAddressfromAddrArg(arg tracee.Argument) (connectedAddress, error) {

	addr, isOk := arg.Value.(map[string]string)
	if !isOk {
		return connectedAddress{}, fmt.Errorf("couldn't convert arg to addr")
	}

	if addr["sa_family"] == "AF_INET" {
		return connectedAddress{ip: addr["sin_addr"], port: addr["sin_port"]}, nil
	} else if addr["sa_family"] == "AF_INET6" {
		return connectedAddress{ip: addr["sin6_addr"], port: addr["sin6_port"]}, nil
	}

	return connectedAddress{}, nil
}
