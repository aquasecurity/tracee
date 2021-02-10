package main

import (
	"encoding/json"
	"fmt"
	"github.com/aquasecurity/tracee/tracee-rules/types"
	tracee "github.com/aquasecurity/tracee/tracee/external"
	"strings"
)

type connectAddrData struct {
	SaFamily string `json:"sa_family"`
	SinPort  string `json:"sin_port"`
	SinAddr  string `json:"sin_addr"`
}

type stdIoOverSocket struct {
	cb              types.SignatureHandler
	processSocketIp map[int]map[int]string
}

func (sig *stdIoOverSocket) Init(cb types.SignatureHandler) error {
	sig.cb = cb
	sig.processSocketIp = make(map[int]map[int]string)

	return nil
}

func (sig *stdIoOverSocket) GetMetadata() (types.SignatureMetadata, error) {
	return types.SignatureMetadata{
		Name:        "STD I/O Over Socket",
		Description: "Redirection of process's standard input/output to socket",
		Tags:        []string{"linux", "container"},
		Properties: map[string]interface{}{
			"Severity":     3,
			"MITRE ATT&CK": "Persistence: Server Software Component",
		},
	}, nil
}

func (sig *stdIoOverSocket) GetSelectedEvents() ([]types.SignatureEventSelector, error) {
	return []types.SignatureEventSelector{
		{Source: "tracee", Name: "connect"},
		{Source: "tracee", Name: "dup2"},
		{Source: "tracee", Name: "dup3"},
		{Source: "tracee", Name: "close"},
	}, nil
}

func (sig *stdIoOverSocket) OnEvent(e types.Event) error {

	eventObj, ok := e.(tracee.Event)
	if !ok {
		return fmt.Errorf("invalid event")
	}

	var connectData connectAddrData
	socketIpMap := make(map[int]string)
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

		addrStr := strings.Replace(addrArg.Value.(string), "'", "\"", -1)
		err = json.Unmarshal([]byte(addrStr), &connectData)
		if err != nil {
			return fmt.Errorf(err.Error())
		}

		if connectData.SaFamily == "AF_INET" {
			socketIpMap[sockfd] = connectData.SinAddr
			sig.processSocketIp[pid] = socketIpMap
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

	}
	return nil
}

func (sig *stdIoOverSocket) OnSignal(s types.Signal) error {
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
