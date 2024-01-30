package ebpf

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events/derive"
	"github.com/aquasecurity/tracee/pkg/extensions"
	"github.com/aquasecurity/tracee/pkg/filters"
	"github.com/aquasecurity/tracee/pkg/global"
	"github.com/aquasecurity/tracee/types/trace"
)

//
// TODO: move to triggerEvents package
//

// triggerSeqOpsIntegrityCheck is used by a Uprobe to trigger an eBPF program that prints
// the seq ops pointers.
func (t *Tracee) triggerSeqOpsIntegrityCheck(event trace.Event) {
	_, ok := extensions.States.GetFromAnyOk(extensions.HookedSeqOps)
	if !ok {
		return
	}

	var seqOpsPointers [len(derive.NetSeqOps)]uint64

	for i, seqName := range derive.NetSeqOps {
		seqOpsStruct, err := global.KSymbols.GetSymbolByOwnerAndName("system", seqName)
		if err != nil {
			continue
		}
		seqOpsPointers[i] = seqOpsStruct[0].Address
	}

	eventHandle := t.triggerContexts.Store(event)

	_ = t.triggerSeqOpsIntegrityCheckCall(uint64(eventHandle), seqOpsPointers)
}

// triggerMemDump is used by a Uprobe to trigger an eBPF program that prints the first
// bytes of requested symbols or addresses.
func (t *Tracee) triggerMemDump(event trace.Event) []error {
	_, ok := extensions.States.GetFromAnyOk(extensions.PrintMemDump)
	if !ok {
		return nil
	}

	errs := []error{}

	// TODO: consider to iterate over given policies when policies are changed
	for p := range t.config.Policies.Map() {
		printMemDumpFilters := p.ArgFilter.GetEventFilters(extensions.PrintMemDump)
		if len(printMemDumpFilters) == 0 {
			errs = append(errs, errfmt.Errorf("policy %d: no address or symbols were provided to print_mem_dump event. "+
				"please provide it via -e print_mem_dump.args.address=<hex address>"+
				", -e print_mem_dump.args.symbol_name=<owner>:<symbol> or "+
				"-e print_mem_dump.args.symbol_name=<symbol> if specifying a system owned symbol", p.ID))
			continue
		}

		var length uint64
		var err error

		lengthFilter, ok := printMemDumpFilters["length"].(*filters.StringFilter)
		if lengthFilter == nil || !ok || len(lengthFilter.Equal()) == 0 {
			length = maxMemDumpLength // default mem dump length
		} else {
			field := lengthFilter.Equal()[0]
			length, err = strconv.ParseUint(field, 10, 64)
			if err != nil {
				errs = append(errs, errfmt.Errorf("policy %d: invalid length provided to print_mem_dump event: %v", p.ID, err))
				continue
			}
		}

		addressFilter, ok := printMemDumpFilters["address"].(*filters.StringFilter)
		if addressFilter != nil && ok {
			for _, field := range addressFilter.Equal() {
				address, err := strconv.ParseUint(field, 16, 64)
				if err != nil {
					errs[p.ID] = errfmt.Errorf("policy %d: invalid address provided to print_mem_dump event: %v", p.ID, err)
					continue
				}
				eventHandle := t.triggerContexts.Store(event)
				_ = t.triggerMemDumpCall(address, length, eventHandle)
			}
		}

		symbolsFilter, ok := printMemDumpFilters["symbol_name"].(*filters.StringFilter)
		if symbolsFilter != nil && ok {
			for _, field := range symbolsFilter.Equal() {
				symbolSlice := strings.Split(field, ":")
				splittedLen := len(symbolSlice)
				var owner string
				var name string
				if splittedLen == 1 {
					owner = "system"
					name = symbolSlice[0]
				} else if splittedLen == 2 {
					owner = symbolSlice[0]
					name = symbolSlice[1]
				} else {
					errs = append(errs, errfmt.Errorf("policy %d: invalid symbols provided to print_mem_dump event: %s - more than one ':' provided", p.ID, field))
					continue
				}
				symbol, err := global.KSymbols.GetSymbolByOwnerAndName(owner, name)
				if err != nil {
					if owner != "system" {
						errs = append(errs, errfmt.Errorf("policy %d: invalid symbols provided to print_mem_dump event: %s - %v", p.ID, field, err))
						continue
					}

					// Checking if the user specified a syscall name
					prefixes := []string{"sys_", "__x64_sys_", "__arm64_sys_"}
					var errSyscall error
					for _, prefix := range prefixes {
						symbol, errSyscall = global.KSymbols.GetSymbolByOwnerAndName(owner, prefix+name)
						if errSyscall == nil {
							err = nil
							break
						}
					}
					if err != nil {
						// syscall not found for the given name using all the prefixes
						valuesStr := make([]string, 0)
						valuesStr = append(valuesStr, owner+"_")
						valuesStr = append(valuesStr, prefixes...)
						valuesStr = append(valuesStr, name)

						values := make([]interface{}, len(valuesStr))
						for i, v := range valuesStr {
							values[i] = v
						}
						attemptedSymbols := fmt.Sprintf("{%s,%s,%s,%s}%s", values...)
						errs = append(errs, errfmt.Errorf("policy %d: invalid symbols provided to print_mem_dump event: %s", p.ID, attemptedSymbols))
						continue
					}
				}
				eventHandle := t.triggerContexts.Store(event)
				_ = t.triggerMemDumpCall(symbol[0].Address, length, uint64(eventHandle))
			}
		}
	}

	return errs
}

//
// Tracee binary symbols for uProbes calls.
//

//go:noinline
func (t *Tracee) triggerSeqOpsIntegrityCheckCall(
	eventHandle uint64,
	seqOpsStruct [len(derive.NetSeqOps)]uint64,
) error {
	return nil
}

//go:noinline
func (t *Tracee) triggerMemDumpCall(
	address uint64,
	length uint64,
	eventHandle uint64,
) error {
	return nil
}
