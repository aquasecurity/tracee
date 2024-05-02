package derive

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"unsafe"

	lru "github.com/hashicorp/golang-lru/v2"
	"kernel.org/pub/linux/libs/security/libcap/cap"

	bpf "github.com/aquasecurity/libbpfgo"

	"github.com/aquasecurity/tracee/pkg/capabilities"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/parse"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/types/trace"
)

var (
	foundHiddenKernModsCache *lru.Cache[uint64, struct{}]
	eventsFromHistoryScan    *lru.Cache[*trace.Event, struct{}]
	allModsMap               *bpf.BPFMap
	newModuleOnlyMap         *bpf.BPFMap
	recentDeletedModulesMap  *bpf.BPFMap
	wakeupChannel            = make(chan ScanRequest)
)

const (
	ProcModules         uint32 = 1 << 0 // A hidden module detected by /proc/modules logic
	kset                       = 1 << 1 // A hidden module detected by kset logic
	modTree                    = 1 << 2 // A hidden module detected by mod tree logic
	NewMod                     = 1 << 3 // A new modules only scan - without HiddenModule flag on, this is not yet a detection. See newModsCheckForHidden
	historyScanFinished        = 1 << 4
	FullScan                   = 1 << 30 // Do a full scan - received after a new module was loaded (and finished running his init function)
	HiddenModule               = 1 << 31 // Submit the module as event to user
)

// ScanRequest the structure that is passed in the wake up channel
type ScanRequest struct {
	Address uint64
	Flags   uint32
}

func HiddenKernelModule() DeriveFunction {
	return deriveMultipleEvents(events.HiddenKernelModule, deriveHiddenKernelModulesArgs())
}

func deriveHiddenKernelModulesArgs() multiDeriveArgsFunction {
	return func(event trace.Event) ([][]interface{}, []error) {
		address, err := parse.ArgVal[uint64](event.Args, "address")
		if err != nil {
			return nil, []error{err}
		}

		if _, found := foundHiddenKernModsCache.Get(address); found {
			return nil, nil // event in cache: already reported.
		}

		flags, err := parse.ArgVal[uint32](event.Args, "flags")
		if err != nil {
			return nil, []error{err}
		}

		// revive:disable

		if flags&HiddenModule != 0 {
			// Empty-block needed: continue an event to user submission.
		} else if flags&FullScan != 0 {
			// No need to send the address: doing a full generic scan.
			wakeupChannel <- ScanRequest{Flags: flags}
			return nil, nil
		} else if flags&NewMod != 0 {
			// Address field unused in this case: use it as start scan time then.
			startScanTime := address
			err := newModsCheckForHidden(startScanTime, flags)
			if err != nil {
				return nil, []error{err}
			}
			return nil, nil
		} else if flags&kset != 0 || flags&modTree != 0 {
			// These types of scan only happens once on tracee's startup.
			// Cache results and only send them out when receiving that the history scan finished successfully
			eventsFromHistoryScan.Add(&event, struct{}{})
			return nil, nil
		} else if flags&historyScanFinished != 0 {
			// Happens only once on tracee's startup when the scan finished (successfully/unsuccessfully)
			return handleHistoryScanFinished(address)
		}

		// revive:enable

		// Add to cache not to report it multiple times
		foundHiddenKernModsCache.Add(address, struct{}{})

		return [][]interface{}{extractFromEvent(event.Args, address)}, nil
	}
}

// InitHiddenKernelModules initializes the module components
func InitHiddenKernelModules(modsMap *bpf.BPFMap, newModMap *bpf.BPFMap, deletedModMap *bpf.BPFMap) error {
	allModsMap = modsMap
	newModuleOnlyMap = newModMap
	recentDeletedModulesMap = deletedModMap

	var err error
	foundHiddenKernModsCache, err = lru.New[uint64, struct{}](2048)
	if err != nil {
		return err
	}

	eventsFromHistoryScan, err = lru.New[*trace.Event, struct{}](50) // If there are more hidden modules found in history scan, it'll report only the size of the LRU
	return err
}

// handleHistoryScanFinished handles the case where the history scan finished
func handleHistoryScanFinished(scanStatus uint64) ([][]interface{}, []error) {
	// Address field unused in this case: use it as a flag for scan status
	if scanStatus == 0 {
		// Finished unsuccessfully, abort publishing events derived from this scan
		// since the scan didn't really finish and the events might be the false positives
		eventsFromHistoryScan.Purge()
		return nil, nil
	}

	var res [][]interface{}
	for {
		e, _, ok := eventsFromHistoryScan.RemoveOldest()
		if !ok {
			break
		}

		address, err := parse.ArgVal[uint64](e.Args, "address")
		if err != nil {
			return nil, []error{err}
		}

		if _, found := foundHiddenKernModsCache.Get(address); found {
			continue
		}

		foundHiddenKernModsCache.Add(address, struct{}{})
		res = append(res, extractFromEvent(e.Args, address)) // Note using the event from LRU and not the event received in the derived event
	}

	return res, nil // Send all the events
}

// extractFromEvent extract arguments from the trace.Argument
func extractFromEvent(args []trace.Argument, address uint64) []interface{} {
	// Parse module name if possible
	var name string
	nameBytes, err := parse.ArgVal[[]byte](args, "name")
	if err != nil {
		name = ""
		// Don't fail hard, submit it without a name!
		logger.Debugw("Failed extracting hidden module name")
	} else {
		// Remove the trailing terminating characters.
		name = string(nameBytes[:bytes.IndexByte(nameBytes[:], 0)])
	}

	// Parse module srcversion if possible
	var srcversion string
	srcversionBytes, err := parse.ArgVal[[]byte](args, "srcversion")
	if err != nil {
		srcversion = ""
		// Don't fail hard, submit it without a srcversion!
		logger.Debugw("Failed extracting hidden module srcversion")
	} else {
		// Remove the trailing terminating characters
		srcversion = string(srcversionBytes[:bytes.IndexByte(srcversionBytes[:], 0)])
	}

	addrHex := fmt.Sprintf("0x%x", address)
	if len(addrHex) == 2 {
		logger.Warnw("Failed converting module address to hex")
	}

	return []interface{}{addrHex, name, srcversion}
}

// newModsCheckForHidden monitors only new added modules (added while tracee is
// running), and reports if they are hidden
func newModsCheckForHidden(startScanTime uint64, flags uint32) error {
	// Since in old kernels it is not possible to iterate on a hashmap, the job
	// is done here (userspace):
	//
	// It goes over a map that is maintained in the eBPF code (on each module
	// insertion/deletion the map is updated), and checks if each module was
	// seen (in modules list), and when was it inserted (to address race
	// conditions).
	//
	// Based on this information, it determines whether it's hidden or not. If
	// found hidden, it sends a message in the channel, which causes the address
	// and the flags to get passed to the lkm submitter program (eBPF), which
	// sends it back to userspace, this time with flags that will cause it to
	// get submitted to the user as an event,
	//
	return capabilities.GetInstance().EBPF(
		func() error {
			var iter = newModuleOnlyMap.Iterator()
			for iter.Next() {
				addr := binary.LittleEndian.Uint64(iter.Key())
				curVal, err := newModuleOnlyMap.GetValue(unsafe.Pointer(&addr))
				if err != nil {
					return err
				}
				insertTime := binary.LittleEndian.Uint64(curVal[0:8])
				lastSeenTime := binary.LittleEndian.Uint64(curVal[8:16])
				if insertTime <= startScanTime && lastSeenTime < startScanTime {
					// It was inserted before the current scan, and we did not
					// see it in the scan: it is hidden. The receiving end will
					// receive the message, trigger the lkm seeker submitter
					// with a specific hidden module
					//
					// Note that we haven't really checked if the module is in
					// the cache before, as we only have the address now.
					//
					if _, found := foundHiddenKernModsCache.Get(addr); !found {
						// It's hidden, and not reported before, report
						wakeupChannel <- ScanRequest{Address: addr, Flags: flags}
					}
				}
			}

			err := iter.Err()
			if err != nil {
				logger.Errorw("clearMap iterator received an error", "error", err.Error())
				return err
			}

			return nil
		},
	)
}

// clearMap a utility to clear a map.
// The caller of this function must provide the necessary capabilities!
func clearMap(bpfMap *bpf.BPFMap) error {
	var err error
	var iter = bpfMap.Iterator()
	for iter.Next() {
		addr := binary.LittleEndian.Uint64(iter.Key())
		err = bpfMap.DeleteKey(unsafe.Pointer(&addr))
		if err != nil {
			logger.Errorw("Err occurred DeleteKey: " + err.Error())
			return err
		}
	}
	err = iter.Err()
	if err != nil {
		logger.Errorw("ClearMap iterator received an error", "error", err.Error())
		return err
	}

	return nil
}

// GetWakeupChannelRead returns the reading-end of the channel
func GetWakeupChannelRead() <-chan ScanRequest {
	return wakeupChannel
}

// ClearModulesState clears the map (while not scanning)
func ClearModulesState() error {
	return capabilities.GetInstance().EBPF(
		func() error {
			_ = clearMap(allModsMap)
			_ = clearMap(recentDeletedModulesMap) // only care for modules deleted in the midst of a scan.
			return nil
		},
	)
}

// FillModulesFromProcFs fills a map with modules from /proc/modules, to be
// checked in kernel-space for inconsistencies.
func FillModulesFromProcFs() error {
	var procModulesBytes []byte
	err := capabilities.GetInstance().Specific(
		func() error {
			var err error
			procModulesBytes, err = os.ReadFile("/proc/modules")
			if err != nil {
				return err
			}

			return nil
		},
		cap.SYSLOG) // Required to get the base addresses of the modules (core_layout.base)
	if err != nil {
		return err
	}

	return capabilities.GetInstance().EBPF(
		func() error {
			for _, line := range strings.Split(string(procModulesBytes), "\n") {
				if len(line) == 0 {
					continue
				}
				lineSplit := strings.Split(line, " ")
				lineLen := len(lineSplit)
				if lineLen < 3 {
					logger.Warnw("Unexpected format in /proc/modules", lineSplit)
					return errors.New("unexpected format in /proc/modules")
				}

				var addr uint64
				candOne := lineSplit[len(lineSplit)-1]
				var finalCand string
				if strings.HasPrefix(candOne, "0x") {
					finalCand = candOne[2:]
				} else {
					candTwo := lineSplit[len(lineSplit)-2]
					finalCand = candTwo[2:]
				}

				addr, parseErr := strconv.ParseUint(finalCand, 16, 64)
				if parseErr != nil {
					logger.Warnw("Unable to parse address from /proc/modules", parseErr)
					return errors.New("unable to parse address from /proc/modules")
				}

				unused := false
				err = allModsMap.Update(unsafe.Pointer(&addr), unsafe.Pointer(&unused))
				if err != nil {
					logger.Errorw("Failed updating allModsMap", err)
					return errors.New("failed updating allModsMap")
				}
			}
			return nil
		},
	)
}
