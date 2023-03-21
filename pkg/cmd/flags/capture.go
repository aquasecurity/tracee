package flags

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	tracee "github.com/aquasecurity/tracee/pkg/ebpf"
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/logger"
)

func captureHelp() string {
	return `Capture artifacts that were written, executed or found to be suspicious.
Captured artifacts will appear in the 'output-path' directory.
Possible options:

[artifact:]write[=/path/prefix*]              capture written files. A filter can be given to only capture file writes whose path starts with some prefix (up to 50 characters). Up to 3 filters can be given.
[artifact:]exec                               capture executed files.
[artifact:]module                             capture loaded kernel modules.
[artifact:]bpf                                capture loaded BPF programs bytecode.
[artifact:]mem                                capture memory regions that had write+execute (w+x) protection, and then changed to execute (x) only.
[artifact:]network                            capture network traffic. Only TCP/UDP/ICMP protocols are currently supported.

dir:/path/to/dir                              path where tracee will save produced artifacts. the artifact will be saved into an 'out' subdirectory. (default: /tmp/tracee).
clear-dir                                     clear the captured artifacts output dir before starting (default: false).

Network:

pcap:[single,process,container,command]       capture separate pcap files organized by single file, files per processes, containers and/or commands
pcap-options:[none,filtered]                  network capturing options:
                                              - none (default): pcap files containing all packets (traced/filtered or not)
                                              - filtered: pcap files containing only traced/filtered packets
                                                          (user needs at least 1 net_packet event to be traced)
pcap-snaplen:[default, headers, max or SIZE]  sets captured payload from each packet:
                                              - default=96b (up to 96 bytes of payload if payload exists)
                                              - headers (up to layer 4, icmp & dns have full headers)
                                              - sizes ended in 'b' or 'kb' (for ipv4, ipv6, tcp, udp):
                                                256b, 512b, 1kb, 2kb, 4kb, ... (up to requested size)
                                              - max (entire packet)

Examples:
  --capture exec                                           | capture executed files into the default output directory
  --capture exec --capture dir:/my/dir --capture clear-dir | delete /my/dir/out and then capture executed files into it
  --capture write=/usr/bin/* --capture write=/etc/*        | capture files that were written into anywhere under /usr/bin/ or /etc/
  --capture exec --output none                             | capture executed files into the default output directory not printing the stream of events

Network Examples:
  --capture net (or network)                               | capture network traffic. default: single pcap file containing all packets (traced/filtered or not)
  --capture net --capture pcap:process,command             | capture network traffic, save pcap files for processes and commands
  --capture net --capture pcap-options:filtered            | capture network traffic. default: single pcap file containing only traced/filtered packets
  --capture net --capture pcap-snaplen:1kb                 | capture network traffic, single pcap file (default), capture up to 1kb from each packet payload
  --capture net --capture pcap-snaplen:max                 | capture network traffic, single pcap file (default), capture full sized packets
  --capture net --capture pcap-snaplen:headers             | capture network traffic, single pcap file (default), capture headers only
  --capture net --capture pcap-snaplen:default             | capture network traffic, single pcap file (default), capture headers + up to 96 bytes of payload
  --capture network --capture pcap:container,command       | capture network traffic, save pcap files for containers and commands

Network notes worth mentioning:

- Pcap files:
  - If you only specify --capture net, you will have a single file with all network traffic.
  - You may use pcap:xxx,yyy to have more than one pcap file, split by different means.

- Pcap options:
  - If you do not specify pcap-options (or set to none), you will capture ALL network traffic into your pcap files.
  - If you specify pcap-options:filtered, events being traced will define what network traffic will be captured.

- Snap Length:
  - If you do not specify a snaplen, the default is headers only (incomplete packets in tcpdump).
  - If you specify "max" as snaplen, you will get full packets contents (pcap files will be large).
  - If you specify "headers" as snaplen, you will only get L2/L3 headers in captured packets.
  - If you specify "headers" but trace for net_packet_dns events, L4 DNS header will be captured.
  - If you specify "headers" but trace for net_packet_http events, only L2/L3 headers will be captured.
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
				return tracee.CaptureConfig{}, errfmt.Errorf("capture write filter cannot be empty")
			}
			filterFileWrite = append(filterFileWrite, pathPrefix)
		} else if cap == "exec" {
			capture.Exec = true
		} else if cap == "module" {
			capture.Module = true
		} else if cap == "mem" {
			capture.Mem = true
		} else if cap == "bpf" {
			capture.Bpf = true
		} else if cap == "network" || cap == "net" || cap == "pcap" {
			// default capture mode: a single pcap file with all traffic
			capture.Net.CaptureSingle = true
			capture.Net.CaptureLength = 96 // default payload
		} else if strings.HasPrefix(cap, "pcap:") {
			capture.Net.CaptureSingle = false // remove default mode
			context := strings.TrimPrefix(cap, "pcap:")
			fields := strings.Split(context, ",")
			for _, field := range fields {
				if field == "single" {
					capture.Net.CaptureSingle = true
				}
				if field == "process" {
					capture.Net.CaptureProcess = true
				}
				if field == "container" {
					capture.Net.CaptureContainer = true
				}
				if field == "command" {
					capture.Net.CaptureCommand = true
				}
			}
			capture.Net.CaptureLength = 96 // default payload
		} else if strings.HasPrefix(cap, "pcap-options:") {
			context := strings.TrimPrefix(cap, "pcap-options:")
			context = strings.ToLower(context) // normalize
			if context == "none" {
				capture.Net.CaptureFiltered = false // proforma
			} else if context == "filtered" {
				capture.Net.CaptureFiltered = true
			}
		} else if strings.HasPrefix(cap, "pcap-snaplen:") {
			context := strings.TrimPrefix(cap, "pcap-snaplen:")
			var amount uint64
			var err error
			context = strings.ToLower(context) // normalize
			if context == "default" {
				amount = 96 // default payload
			} else if context == "max" {
				amount = (1 << 16) - 1 // max length for IP packets
			} else if context == "headers" {
				amount = 0 // sets headers only length for capturing (default)
			} else if strings.HasSuffix(context, "kb") ||
				strings.HasSuffix(context, "k") {
				context = strings.TrimSuffix(context, "kb")
				context = strings.TrimSuffix(context, "k")
				amount, err = strconv.ParseUint(context, 10, 64)
				amount *= 1024 // result in bytes
			} else if strings.HasSuffix(context, "b") {
				context = strings.TrimSuffix(context, "b")
				amount, err = strconv.ParseUint(context, 10, 64)
			} else {
				return tracee.CaptureConfig{}, errfmt.Errorf("could not parse pcap snaplen: missing b or kb ?")
			}
			if err != nil {
				return tracee.CaptureConfig{}, errfmt.Errorf("could not parse pcap snaplen: %v", err)
			}
			if amount >= (1 << 16) {
				amount = (1 << 16) - 1
			}
			capture.Net.CaptureLength = uint32(amount) // of packet length to be captured in bytes
		} else if cap == "clear-dir" {
			clearDir = true
		} else if strings.HasPrefix(cap, "dir:") {
			outDir = strings.TrimPrefix(cap, "dir:")
			if len(outDir) == 0 {
				return tracee.CaptureConfig{}, errfmt.Errorf("capture output dir cannot be empty")
			}
		} else {
			return tracee.CaptureConfig{}, errfmt.Errorf("invalid capture option specified, use '--capture help' for more info")
		}
	}
	capture.FilterFileWrite = filterFileWrite

	capture.OutputPath = filepath.Join(outDir, "out")
	if !clearDir {
		return capture, nil
	}

	if err := os.RemoveAll(capture.OutputPath); err != nil {
		logger.Warnw("Removing all", "error", err)
	}

	return capture, nil
}
