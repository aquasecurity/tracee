package flags

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	tracee "github.com/aquasecurity/tracee/pkg/ebpf"
)

func captureHelp() string {
	return `Capture artifacts that were written, executed or found to be suspicious.
Captured artifacts will appear in the 'output-path' directory.
Possible options:

[artifact:]write[=/path/prefix*]   capture written files. A filter can be given to only capture file writes whose path starts with some prefix (up to 50 characters). Up to 3 filters can be given.
[artifact:]exec                    capture executed files.
[artifact:]module                  capture loaded kernel modules.
[artifact:]mem                     capture memory regions that had write+execute (w+x) protection, and then changed to execute (x) only.
[artifact:]network                 capture network traffic. Only TCP/UDP/ICMP protocols are currently supported.

dir:/path/to/dir                    path where tracee will save produced artifacts. the artifact will be saved into an 'out' subdirectory. (default: /tmp/tracee).
profile                             creates a runtime profile of program executions and their metadata for forensics use.
clear-dir                           clear the captured artifacts output dir before starting (default: false).
pcap:[process,container,command]    capture separate pcap files organized by processes, containers and/or commands

Examples:
  --capture exec                                           | capture executed files into the default output directory
  --capture exec --capture dir:/my/dir --capture clear-dir | delete /my/dir/out and then capture executed files into it
  --capture write=/usr/bin/* --capture write=/etc/*        | capture files that were written into anywhere under /usr/bin/ or /etc/
  --capture profile                                        | capture executed files and create a runtime profile in the output directory
  --capture net                                            | capture network traffic. default: pcap for processes only (check pcap options)
  --capture network                                        | capture network traffic. default: pcap for processes only (check pcap options)
  --capture net --capture pcap:process,command             | capture network traffic, save pcap files for processes and commands
  --capture network --capture pcap:container,command       | capture network traffic, save pcap files for containers and commands
  --capture exec --output none                             | capture executed files into the default output directory not printing the stream of events

Use this flag multiple times to choose multiple capture options
`
}

func PrepareCapture(captureSlice []string) (tracee.CaptureConfig, error) {
	capture := tracee.CaptureConfig{}

	outDir := "/tmp/tracee"
	clearDir := false

	var filterFileWrite []string
	for i := range captureSlice {
		cap := captureSlice[i]
		if strings.HasPrefix(cap, "artifact:write") ||
			strings.HasPrefix(cap, "artifact:exec") ||
			strings.HasPrefix(cap, "artifact:mem") ||
			strings.HasPrefix(cap, "artifact:module") {
			cap = strings.TrimPrefix(cap, "artifact:")
		}
		if cap == "write" {
			capture.FileWrite = true
		} else if strings.HasPrefix(cap, "write=") && strings.HasSuffix(cap, "*") {
			capture.FileWrite = true
			pathPrefix := strings.TrimSuffix(strings.TrimPrefix(cap, "write="), "*")
			if len(pathPrefix) == 0 {
				return tracee.CaptureConfig{}, fmt.Errorf("capture write filter cannot be empty")
			}
			filterFileWrite = append(filterFileWrite, pathPrefix)
		} else if cap == "exec" {
			capture.Exec = true
		} else if cap == "module" {
			capture.Module = true
		} else if cap == "mem" {
			capture.Mem = true
		} else if cap == "network" || cap == "net" {
			capture.Net.CaptureProcess = true
		} else if strings.HasPrefix(cap, "pcap:") {
			// TODO: turn default capture mode to a single pcap file like it was
			capture.Net.CaptureProcess = true // process is default capture mode
			context := strings.TrimPrefix(cap, "pcap:")
			fields := strings.Split(context, ",")
			found := false
			for _, field := range fields {
				if field == "process" {
					found = true
				}
				if field == "container" {
					capture.Net.CaptureContainer = true
				}
				if field == "command" {
					capture.Net.CaptureCommand = true
				}
			}
			if !found {
				capture.Net.CaptureProcess = false
			}
		} else if cap == "clear-dir" {
			clearDir = true
		} else if strings.HasPrefix(cap, "dir:") {
			outDir = strings.TrimPrefix(cap, "dir:")
			if len(outDir) == 0 {
				return tracee.CaptureConfig{}, fmt.Errorf("capture output dir cannot be empty")
			}
		} else if cap == "profile" {
			capture.Exec = true
			capture.Profile = true
		} else {
			return tracee.CaptureConfig{}, fmt.Errorf("invalid capture option specified, use '--capture help' for more info")
		}
	}
	capture.FilterFileWrite = filterFileWrite

	capture.OutputPath = filepath.Join(outDir, "out")
	if clearDir {
		os.RemoveAll(capture.OutputPath)
	}

	return capture, nil
}
