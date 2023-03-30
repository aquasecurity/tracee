package derive

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"unsafe"

	lru "github.com/hashicorp/golang-lru"
	"kernel.org/pub/linux/libs/security/libcap/cap"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/helpers"

	"github.com/aquasecurity/tracee/pkg/capabilities"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/parse"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/types/trace"
)

var (
	foundHiddenKernModsCache *lru.Cache
)

func HiddenKernelModule() DeriveFunction {
	return deriveSingleEvent(events.HiddenKernelModule, deriveHiddenKernelModulesArgs())
}

func deriveHiddenKernelModulesArgs() deriveArgsFunction {
	return func(event trace.Event) ([]interface{}, error) {
		address, err := parse.ArgVal[uint64](&event, "address")
		if err != nil {
			return nil, err
		}

		name, err := parse.ArgVal[[]byte](&event, "name")
		if err != nil {
			return nil, err
		}

		if _, found := foundHiddenKernModsCache.Get(address); found {
			return nil, nil // already reported this event - no need to report again
		} else {
			foundHiddenKernModsCache.Add(address, struct{}{}) // so we won't report multiple times
		}

		addrHex := fmt.Sprintf("0x%x", address)
		if len(addrHex) == 2 {
			logger.Warnw("Failed converting module address to hex")
		}

		return []interface{}{addrHex, string(name)}, nil
	}
}

func InitFoundHiddenModulesCache() error {
	var err error
	foundHiddenKernModsCache, err = lru.New(2048)
	return err
}

func clearMap(bpfMap *bpf.BPFMap) error {
	var err error

	var iter = bpfMap.Iterator()
	for iter.Next() {
		addr := binary.LittleEndian.Uint64(iter.Key())
		err = bpfMap.DeleteKey(unsafe.Pointer(&addr))

		if err != nil {
			logger.Errorw("err occurred DeleteKey: " + err.Error())
			return err
		}
	}

	return nil
}

func ClearModulesState(modsMap *bpf.BPFMap) {
	_ = clearMap(modsMap)
}

func FillModulesFromProcFs(kernelSymbols helpers.KernelSymbolTable, modulesFromProcFs *bpf.BPFMap) error {
	err := capabilities.GetInstance().Requested(
		func() error {
			file, err := os.Open("/proc/modules")
			if err != nil {
				logger.Errorw("error opening /proc/modules", err)
				return errors.New("error opening /proc/modules")
			}
			defer func() {
				if err := file.Close(); err != nil {
					logger.Errorw("error closing /proc/modules", err)
				}
			}()

			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := scanner.Text()
				lineSplit := strings.Split(line, " ")
				lineLen := len(lineSplit)
				if lineLen < 3 {
					logger.Warnw("Unexpected format in /proc/modules", lineSplit)
					return errors.New("unexpected format in /proc/modules")
				}

				moduleName := lineSplit[0]
				var addr uint64

				// get module address from kallsyms since /proc/modules doesn't return the address to __this_module
				ks, err := kernelSymbols.GetSymbolByName(moduleName, "__this_module")
				if err != nil {
					// this most likely means /proc/kallsyms is hooked while /proc/modules isn't
					// fallback to use the address in /proc/modules
					candOne := lineSplit[len(lineSplit)-1]
					candTwo := lineSplit[len(lineSplit)-2]
					var finalCand string
					if strings.HasPrefix(candOne, "0x") {
						finalCand = candOne[2:]
					} else {
						finalCand = candTwo[2:]
					}

					result, parseErr := strconv.ParseUint(finalCand, 16, 64)
					if parseErr == nil {
						addr = result
					}
				} else {
					addr = ks.Address
				}
				seenInProcModules := true
				err = modulesFromProcFs.Update(unsafe.Pointer(&addr), unsafe.Pointer(&seenInProcModules))
				if err != nil {
					logger.Errorw("Failed updating modulesFromProcFs", err)
					return errors.New("failed updating modulesFromProcFs")
				}
			}

			if err := scanner.Err(); err != nil {
				logger.Errorw("scanner reported error: ", err)
			}

			return nil
		},
		cap.DAC_OVERRIDE,
	)
	return err

}
