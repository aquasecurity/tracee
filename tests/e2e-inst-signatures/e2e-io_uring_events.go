package main

import (
	"errors"
	"fmt"

	"github.com/aquasecurity/tracee/common/parsers"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type e2eIoUring struct {
	cb            detect.SignatureHandler
	ioIssueSqe    bool
	ioWrite       bool
	ioUringCreate bool
	device        uint32
	inode         uint64
}

func (sig *e2eIoUring) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	return nil
}

func (sig *e2eIoUring) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "IO_URING_EVENTS",
		EventName:   "IO_URING_EVENTS",
		Version:     "0.1.0",
		Name:        "io_uring events Test",
		Description: "Instrumentation events E2E Tests: io_uring events",
		Tags:        []string{"e2e", "instrumentation"},
	}, nil
}

func (sig *e2eIoUring) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "io_write"},
		{Source: "tracee", Name: "io_issue_sqe"},
		{Source: "tracee", Name: "io_uring_create"},
	}, nil
}

func (sig *e2eIoUring) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return errors.New("failed to cast event's payload")
	}

	switch eventObj.EventName {
	case "io_write":
		err := sig.handleIoWrite(event)
		if err != nil {
			return err
		}
		sig.ioWrite = true
	case "io_issue_sqe":
		err := sig.handleIoIssueSqe(event)
		if err != nil {
			return err
		}
		sig.ioIssueSqe = true
	case "io_uring_create":
		err := sig.handleIoUringCreate(event)
		if err != nil {
			return err
		}
		sig.ioUringCreate = true
	}

	if sig.ioWrite && sig.ioIssueSqe && sig.ioUringCreate {
		m, _ := sig.GetMetadata()
		sig.cb(&detect.Finding{
			SigMetadata: m,
			Event:       event,
			Data:        map[string]interface{}{},
		})
	}

	return nil
}

func (sig *e2eIoUring) handleIoWrite(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return errors.New("failed to cast event's payload")
	}

	// Validate path
	path, err := eventObj.GetStringArgumentByName("path")
	if err != nil {
		return err
	}
	if path != "/tmp/io_uring_writev.txt" {
		return fmt.Errorf("unexpected path: expected /tmp/io_uring_writev.txt, got %s", path)
	}

	// Validate device matches io_issue_sqe
	device, err := eventObj.GetIntArgumentByName("device")
	if err != nil {
		return err
	}
	if sig.device != 0 && uint32(device) != sig.device {
		return fmt.Errorf("device mismatch: expected %d, got %d", sig.device, device)
	}

	// Validate inode matches io_issue_sqe
	inode, err := eventObj.GetIntArgumentByName("inode")
	if err != nil {
		return err
	}
	if sig.inode != 0 && uint64(inode) != sig.inode {
		return fmt.Errorf("inode mismatch: expected %d, got %d", sig.inode, inode)
	}

	// Validate pos
	pos, err := eventObj.GetIntArgumentByName("pos")
	if err != nil {
		return err
	}
	if pos < 0 {
		return fmt.Errorf("pos should not be negative: %d", pos)
	}

	// Validate len
	length, err := eventObj.GetIntArgumentByName("len")
	if err != nil {
		return err
	}
	if length <= 0 {
		return fmt.Errorf("len should be positive: %d", length)
	}

	// Validate buf pointer is set
	buf, err := eventObj.GetUintArgumentByName("buf")
	if err != nil {
		return err
	}
	if buf == 0 {
		return errors.New("buf pointer should not be null")
	}

	// Validate worker_host_tid is set
	workerTid, err := eventObj.GetIntArgumentByName("worker_host_tid")
	if err != nil {
		return err
	}
	if workerTid == 0 {
		return errors.New("worker_host_tid should not be 0")
	}

	return nil
}

func (sig *e2eIoUring) handleIoIssueSqe(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return errors.New("failed to cast event's payload")
	}

	// Validate path
	path, err := eventObj.GetStringArgumentByName("path")
	if err != nil {
		return err
	}
	if path != "/tmp/io_uring_writev.txt" {
		return fmt.Errorf("unexpected path: expected /tmp/io_uring_writev.txt, got %s", path)
	}

	// Validate and store device
	device, err := eventObj.GetIntArgumentByName("device")
	if err != nil {
		return err
	}
	if device == 0 {
		return errors.New("device should not be 0")
	}
	sig.device = uint32(device)

	// Validate and store inode
	inode, err := eventObj.GetIntArgumentByName("inode")
	if err != nil {
		return err
	}
	if inode == 0 {
		return errors.New("inode should not be 0")
	}
	sig.inode = uint64(inode)

	// Validate opcode (IORING_OP_WRITEV = 1)
	opcode, err := eventObj.GetIntArgumentByName("opcode")
	if err != nil {
		return err
	}
	if opcode != int(parsers.IORING_OP_WRITEV.Value()) {
		return fmt.Errorf("unexpected opcode: expected 1 (IORING_OP_WRITEV), got %d", opcode)
	}

	// Validate user_data is set
	userData, err := eventObj.GetIntArgumentByName("user_data")
	if err != nil {
		return err
	}
	if userData == 0 {
		return errors.New("user_data should not be 0")
	}

	return nil
}

func (sig *e2eIoUring) handleIoUringCreate(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return errors.New("failed to cast event's payload")
	}

	// Validate sq_entries
	sqEntries, err := eventObj.GetIntArgumentByName("sq_entries")
	if err != nil {
		return err
	}
	if sqEntries != 16 {
		return fmt.Errorf("unexpected sq_entries: expected 16, got %d", sqEntries)
	}

	// Validate cq_entries
	cqEntries, err := eventObj.GetIntArgumentByName("cq_entries")
	if err != nil {
		return err
	}
	if cqEntries != 32 {
		return fmt.Errorf("unexpected cq_entries: expected 32, got %d", cqEntries)
	}

	// Validate ctx pointer is set
	ctx, err := eventObj.GetUintArgumentByName("ctx")
	if err != nil {
		return err
	}
	if ctx == 0 {
		return errors.New("ctx pointer should not be null")
	}

	return nil
}

func (sig *e2eIoUring) OnSignal(s detect.Signal) error {
	return nil
}

func (sig *e2eIoUring) Close() {}
