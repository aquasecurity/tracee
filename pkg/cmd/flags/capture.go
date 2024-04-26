package flags

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/aquasecurity/tracee/pkg/config"
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/logger"
)

func captureHelp() string {
	return `Capture artifacts that were written, executed or found to be suspicious.
Captured artifacts will appear in the 'output-path' directory.
Possible options:

[artifact:]write[=/path/prefix*]              capture written files. A filter can be given to only capture file writes whose path starts with some prefix (up to 50 characters). Up to 3 filters can be given.
[artifact:]read[=/path/prefix*]               capture read files. A filter can be given to only capture file reads whose path starts with some prefix (up to 50 characters). Up to 3 filters can be given.
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

File Capture Filters
Files capture upon read/write can be filtered to catch only specific IO operations.
The different filter types have logical 'and' between them, but logical 'or' between filters of the same type.
The filter is given in the following format - <read/write>:<filter_type>=<filter_value>
Filters types:
path               A filter for the file path prefix (up to 50 characters). Up to 3 filters can be given. Identical to using '<read/write>=/path/prefix*'.
type               A file type from the following options: 'regular', 'pipe', 'socket' and 'elf'.
fd                 The file descriptor of the file. Can be one of the three standards - 'stdin', 'stdout' and 'stderr'.


Examples:
  --capture exec                                           | capture executed files into the default output directory
  --capture exec --capture dir:/my/dir --capture clear-dir | delete /my/dir/out and then capture executed files into it
  --capture write=/usr/bin/* --capture write=/etc/*        | capture files that were written into anywhere under /usr/bin/ or /etc/
  --capture exec --output none                             | capture executed files into the default output directory not printing the stream of events
  --capture write:type=socket --capture write:fd=stdout    | capture file writes to socket files which are the 'stdout' of the writing process

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

func PrepareCapture(captureSlice []string, newBinary bool) (config.CaptureConfig, error) {
	capture := config.CaptureConfig{}

	outDir := "/tmp/tracee"
	clearDir := false

	for i := range captureSlice {
		c := captureSlice[i]
		if strings.HasPrefix(c, "artifact:write") ||
			strings.HasPrefix(c, "artifact:exec") ||
			strings.HasPrefix(c, "artifact:mem") ||
			strings.HasPrefix(c, "artifact:module") {
			c = strings.TrimPrefix(c, "artifact:")
		}
		if strings.HasPrefix(c, "write") {
			err := parseFileCaptureOption("write", c, &capture.FileWrite)
			if err != nil {
				return config.CaptureConfig{}, err
			}
		} else if strings.HasPrefix(c, "read") {
			err := parseFileCaptureOption("read", c, &capture.FileRead)
			if err != nil {
				return config.CaptureConfig{}, err
			}
		} else if c == "exec" {
			capture.Exec = true
		} else if c == "module" {
			capture.Module = true
		} else if c == "mem" {
			capture.Mem = true
		} else if c == "bpf" {
			capture.Bpf = true
		} else if c == "network" || c == "net" || c == "pcap" {
			// default capture mode: a single pcap file with all traffic
			capture.Net.CaptureSingle = true
			capture.Net.CaptureLength = 96 // default payload
		} else if strings.HasPrefix(c, "pcap:") {
			capture.Net.CaptureSingle = false // remove default mode
			scope := strings.TrimPrefix(c, "pcap:")
			fields := strings.Split(scope, ",")
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
		} else if strings.HasPrefix(c, "pcap-options:") {
			scope := strings.TrimPrefix(c, "pcap-options:")
			scope = strings.ToLower(scope) // normalize
			if scope == "none" {
				capture.Net.CaptureFiltered = false // proforma
			} else if scope == "filtered" {
				capture.Net.CaptureFiltered = true
			}
		} else if strings.HasPrefix(c, "pcap-snaplen:") {
			scope := strings.TrimPrefix(c, "pcap-snaplen:")
			var amount uint64
			var err error
			scope = strings.ToLower(scope) // normalize
			if scope == "default" {
				amount = 96 // default payload
			} else if scope == "max" {
				amount = (1 << 16) - 1 // max length for IP packets
			} else if scope == "headers" {
				amount = 0 // sets headers only length for capturing (default)
			} else if strings.HasSuffix(scope, "kb") ||
				strings.HasSuffix(scope, "k") {
				scope = strings.TrimSuffix(scope, "kb")
				scope = strings.TrimSuffix(scope, "k")
				amount, err = strconv.ParseUint(scope, 10, 64)
				amount *= 1024 // result in bytes
			} else if strings.HasSuffix(scope, "b") {
				scope = strings.TrimSuffix(scope, "b")
				amount, err = strconv.ParseUint(scope, 10, 64)
			} else {
				return config.CaptureConfig{}, errfmt.Errorf("could not parse pcap snaplen: missing b or kb ?")
			}
			if err != nil {
				return config.CaptureConfig{}, errfmt.Errorf("could not parse pcap snaplen: %v", err)
			}
			if amount >= (1 << 16) {
				amount = (1 << 16) - 1
			}
			capture.Net.CaptureLength = uint32(amount) // of packet length to be captured in bytes
		} else if c == "clear-dir" {
			clearDir = true
		} else if strings.HasPrefix(c, "dir:") {
			outDir = strings.TrimPrefix(c, "dir:")
			if len(outDir) == 0 {
				return config.CaptureConfig{}, errfmt.Errorf("capture output dir cannot be empty")
			}
		} else {
			if newBinary {
				return config.CaptureConfig{}, errfmt.Errorf("invalid capture option specified, run 'man capture' for more info")
			}

			return config.CaptureConfig{}, errfmt.Errorf("invalid capture option specified, use '--capture help' for more info")
		}
	}

	capture.OutputPath = filepath.Join(outDir, "out")
	if !clearDir {
		return capture, nil
	}

	if err := os.RemoveAll(capture.OutputPath); err != nil {
		logger.Warnw("Removing all", "error", err)
	}

	return capture, nil
}

// parseFileCaptureOption parse file capture cmdline argument option of all supported formats.
func parseFileCaptureOption(arg string, cap string, captureConfig *config.FileCaptureConfig) error {
	captureConfig.Capture = true
	if cap == arg {
		return nil
	}
	if strings.HasPrefix(cap, fmt.Sprintf("%s=", arg)) {
		cap = strings.Replace(cap, fmt.Sprintf("%s=", arg), fmt.Sprintf("%s:path=", arg), 1)
	}
	optAndValue := strings.SplitN(cap, ":", 2)
	if len(optAndValue) != 2 || optAndValue[0] != arg {
		return fmt.Errorf("invalid capture option specified, use '--capture help' for more info")
	}
	err := parseFileCaptureSubOption(optAndValue[1], captureConfig)
	return err
}

// parseFileCaptureSubOption parse file capture cmdline sub-option of the format '<sub-opt>=<value>' and update the
// configuration according to the value.
func parseFileCaptureSubOption(option string, captureConfig *config.FileCaptureConfig) error {
	optAndValue := strings.SplitN(option, "=", 2)
	if len(optAndValue) != 2 || len(optAndValue[1]) == 0 {
		return fmt.Errorf("invalid capture option specified, use '--capture help' for more info")
	}
	opt := optAndValue[0]
	value := optAndValue[1]
	switch opt {
	case "path":
		if !strings.HasSuffix(option, "*") {
			return fmt.Errorf("file path filter should end with *")
		}
		pathPrefix := strings.TrimSuffix(value, "*")
		if len(pathPrefix) == 0 {
			return fmt.Errorf("capture path filter cannot be empty")
		}
		captureConfig.PathFilter = append(captureConfig.PathFilter, pathPrefix)
	case "type":
		typeFilter := strings.TrimPrefix(option, "type=")
		filterFlag, err := parseFileCaptureType(typeFilter)
		if err != nil {
			return err
		}
		captureConfig.TypeFilter |= filterFlag
	case "fd":
		typeFilter := strings.TrimPrefix(option, "fd=")
		filterFlag, err := parseFileCaptureFDs(typeFilter)
		if err != nil {
			return err
		}
		captureConfig.TypeFilter |= filterFlag
	default:
		return fmt.Errorf("unrecognized file capture option: %s", opt)
	}

	return nil
}

var captureFileTypeStringToFlag = map[string]config.FileCaptureType{
	"pipe":    config.CapturePipeFiles,
	"socket":  config.CaptureSocketFiles,
	"regular": config.CaptureRegularFiles,
	"elf":     config.CaptureELFFiles,
}

// parseFileCaptureType parse file type string to its matching bit-flag value
func parseFileCaptureType(filter string) (config.FileCaptureType, error) {
	filterFlag, ok := captureFileTypeStringToFlag[filter]
	if ok {
		return filterFlag, nil
	}
	return 0, fmt.Errorf("unsupported file type filter value for capture - %s", filter)
}

var captureFDsStringToFlag = map[string]config.FileCaptureType{
	"stdin":  config.CaptureStdinFiles,
	"stdout": config.CaptureStdoutFiles,
	"stderr": config.CaptureStderrFiles,
}

// parseFileCaptureFDs parse file standard FD string to its matching bit-flag value
func parseFileCaptureFDs(filter string) (config.FileCaptureType, error) {
	filterFlag, ok := captureFDsStringToFlag[filter]
	if ok {
		return filterFlag, nil
	}
	return 0, fmt.Errorf("unsupported file FD filter value for capture - %s", filter)
}
