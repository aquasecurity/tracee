package yaml

import (
	"errors"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"

	"github.com/aquasecurity/tracee/api/v1beta1/datastores"
)

// registerDatastoreFunctions registers all datastore-related CEL functions
// Returns CEL environment options for datastore functions
// If registry is nil (during validation), functions will return null/empty results
func registerDatastoreFunctions(registry datastores.Registry) []cel.EnvOption {
	return []cel.EnvOption{
		// ProcessStore functions
		cel.Function("process.get",
			cel.Overload("process_get_uint64",
				[]*cel.Type{cel.UintType},
				cel.DynType, // Returns ProcessInfo struct or null
				cel.UnaryBinding(createProcessGetBinding(registry)),
			),
		),
		cel.Function("process.getAncestry",
			cel.Overload("process_getAncestry_uint64_int",
				[]*cel.Type{cel.UintType, cel.IntType},
				cel.ListType(cel.DynType), // Returns list of ProcessInfo
				cel.BinaryBinding(createProcessGetAncestryBinding(registry)),
			),
		),
		cel.Function("process.getChildren",
			cel.Overload("process_getChildren_uint64",
				[]*cel.Type{cel.UintType},
				cel.ListType(cel.DynType), // Returns list of ProcessInfo
				cel.UnaryBinding(createProcessGetChildrenBinding(registry)),
			),
		),

		// ContainerStore functions
		cel.Function("container.get",
			cel.Overload("container_get_string",
				[]*cel.Type{cel.StringType},
				cel.DynType, // Returns ContainerInfo or null
				cel.UnaryBinding(createContainerGetBinding(registry)),
			),
		),
		cel.Function("container.getByName",
			cel.Overload("container_getByName_string",
				[]*cel.Type{cel.StringType},
				cel.DynType, // Returns ContainerInfo or null
				cel.UnaryBinding(createContainerGetByNameBinding(registry)),
			),
		),

		// SystemStore function (no args, returns SystemInfo)
		cel.Function("system.info",
			cel.Overload("system_info",
				[]*cel.Type{},
				cel.DynType, // Returns SystemInfo
				cel.FunctionBinding(func(args ...ref.Val) ref.Val {
					return createSystemInfoBinding(registry)()
				}),
			),
		),

		// KernelSymbolStore functions
		cel.Function("kernel.resolveSymbol",
			cel.Overload("kernel_resolveSymbol_uint64",
				[]*cel.Type{cel.UintType},
				cel.ListType(cel.DynType), // Returns list of SymbolInfo
				cel.UnaryBinding(createResolveSymbolBinding(registry)),
			),
		),
		cel.Function("kernel.getSymbolAddress",
			cel.Overload("kernel_getSymbolAddress_string",
				[]*cel.Type{cel.StringType},
				cel.UintType, // Returns address or 0 if not found
				cel.UnaryBinding(createGetSymbolAddressBinding(registry)),
			),
		),

		// DNSStore function
		cel.Function("dns.getResponse",
			cel.Overload("dns_getResponse_string",
				[]*cel.Type{cel.StringType},
				cel.DynType, // Returns DNSResponse or null
				cel.UnaryBinding(createDNSGetResponseBinding(registry)),
			),
		),

		// SyscallStore functions
		cel.Function("syscall.getName",
			cel.Overload("syscall_getName_int",
				[]*cel.Type{cel.IntType},
				cel.StringType, // Returns name or empty string
				cel.UnaryBinding(createSyscallGetNameBinding(registry)),
			),
		),
		cel.Function("syscall.getId",
			cel.Overload("syscall_getId_string",
				[]*cel.Type{cel.StringType},
				cel.IntType, // Returns ID or -1 if not found
				cel.UnaryBinding(createSyscallGetIdBinding(registry)),
			),
		),
	}
}

// ProcessStore bindings

func createProcessGetBinding(registry datastores.Registry) func(ref.Val) ref.Val {
	return func(arg ref.Val) ref.Val {
		// Handle nil registry (validation mode)
		if registry == nil {
			return types.NullValue
		}

		entityId, ok := arg.Value().(uint64)
		if !ok {
			return types.NewErr("process.get: argument must be uint64")
		}

		processStore := registry.Processes()
		if processStore == nil {
			return types.NullValue
		}

		procInfo, err := processStore.GetProcess(uint32(entityId))
		if err != nil {
			if errors.Is(err, datastores.ErrNotFound) {
				return types.NullValue
			}
			return types.NewErr("process.get: %v", err)
		}

		return convertProcessInfoToCEL(procInfo)
	}
}

func createProcessGetAncestryBinding(registry datastores.Registry) func(ref.Val, ref.Val) ref.Val {
	return func(entityIdVal, maxDepthVal ref.Val) ref.Val {
		// Handle nil registry (validation mode)
		if registry == nil {
			return types.DefaultTypeAdapter.NativeToValue([]any{})
		}

		entityId, ok := entityIdVal.Value().(uint64)
		if !ok {
			return types.NewErr("process.getAncestry: first arg must be uint64")
		}

		maxDepth, ok := maxDepthVal.Value().(int64)
		if !ok {
			return types.NewErr("process.getAncestry: second arg must be int")
		}

		processStore := registry.Processes()
		if processStore == nil {
			return types.DefaultTypeAdapter.NativeToValue([]any{})
		}

		ancestry, err := processStore.GetAncestry(uint32(entityId), int(maxDepth))
		if err != nil {
			return types.NewErr("process.getAncestry: %v", err)
		}

		return convertProcessListToCEL(ancestry)
	}
}

func createProcessGetChildrenBinding(registry datastores.Registry) func(ref.Val) ref.Val {
	return func(arg ref.Val) ref.Val {
		// Handle nil registry (validation mode)
		if registry == nil {
			return types.DefaultTypeAdapter.NativeToValue([]any{})
		}

		entityId, ok := arg.Value().(uint64)
		if !ok {
			return types.NewErr("process.getChildren: argument must be uint64")
		}

		processStore := registry.Processes()
		if processStore == nil {
			return types.DefaultTypeAdapter.NativeToValue([]any{})
		}

		children, err := processStore.GetChildProcesses(uint32(entityId))
		if err != nil {
			return types.NewErr("process.getChildren: %v", err)
		}

		return convertProcessListToCEL(children)
	}
}

// ContainerStore bindings

func createContainerGetBinding(registry datastores.Registry) func(ref.Val) ref.Val {
	return func(arg ref.Val) ref.Val {
		// Handle nil registry (validation mode)
		if registry == nil {
			return types.NullValue
		}

		containerId, ok := arg.Value().(string)
		if !ok {
			return types.NewErr("container.get: argument must be string")
		}

		containerStore := registry.Containers()
		if containerStore == nil {
			return types.NullValue
		}

		containerInfo, err := containerStore.GetContainer(containerId)
		if err != nil {
			if errors.Is(err, datastores.ErrNotFound) {
				return types.NullValue
			}
			return types.NewErr("container.get: %v", err)
		}

		return convertContainerInfoToCEL(containerInfo)
	}
}

func createContainerGetByNameBinding(registry datastores.Registry) func(ref.Val) ref.Val {
	return func(arg ref.Val) ref.Val {
		// Handle nil registry (validation mode)
		if registry == nil {
			return types.NullValue
		}

		containerName, ok := arg.Value().(string)
		if !ok {
			return types.NewErr("container.getByName: argument must be string")
		}

		containerStore := registry.Containers()
		if containerStore == nil {
			return types.NullValue
		}

		containerInfo, err := containerStore.GetContainerByName(containerName)
		if err != nil {
			if errors.Is(err, datastores.ErrNotFound) {
				return types.NullValue
			}
			return types.NewErr("container.getByName: %v", err)
		}

		return convertContainerInfoToCEL(containerInfo)
	}
}

// SystemStore binding

func createSystemInfoBinding(registry datastores.Registry) func() ref.Val {
	return func() ref.Val {
		// Handle nil registry (validation mode)
		if registry == nil {
			return types.NullValue
		}

		systemStore := registry.System()
		if systemStore == nil {
			return types.NullValue
		}

		systemInfo := systemStore.GetSystemInfo()
		return convertSystemInfoToCEL(systemInfo)
	}
}

// KernelSymbolStore bindings

func createResolveSymbolBinding(registry datastores.Registry) func(ref.Val) ref.Val {
	return func(arg ref.Val) ref.Val {
		// Handle nil registry (validation mode)
		if registry == nil {
			return types.DefaultTypeAdapter.NativeToValue([]any{})
		}

		addr, ok := arg.Value().(uint64)
		if !ok {
			return types.NewErr("kernel.resolveSymbol: argument must be uint64")
		}

		kernelStore := registry.KernelSymbols()
		if kernelStore == nil {
			return types.DefaultTypeAdapter.NativeToValue([]any{})
		}

		symbols, err := kernelStore.ResolveSymbolByAddress(addr)
		if err != nil {
			if errors.Is(err, datastores.ErrNotFound) {
				return types.DefaultTypeAdapter.NativeToValue([]any{})
			}
			return types.NewErr("kernel.resolveSymbol: %v", err)
		}

		return convertSymbolListToCEL(symbols)
	}
}

func createGetSymbolAddressBinding(registry datastores.Registry) func(ref.Val) ref.Val {
	return func(arg ref.Val) ref.Val {
		// Handle nil registry (validation mode)
		if registry == nil {
			return types.Uint(0)
		}

		symbolName, ok := arg.Value().(string)
		if !ok {
			return types.NewErr("kernel.getSymbolAddress: argument must be string")
		}

		kernelStore := registry.KernelSymbols()
		if kernelStore == nil {
			return types.Uint(0)
		}

		addr, err := kernelStore.GetSymbolAddress(symbolName)
		if err != nil {
			if errors.Is(err, datastores.ErrNotFound) {
				return types.Uint(0)
			}
			return types.NewErr("kernel.getSymbolAddress: %v", err)
		}

		return types.Uint(addr)
	}
}

// DNSStore binding

func createDNSGetResponseBinding(registry datastores.Registry) func(ref.Val) ref.Val {
	return func(arg ref.Val) ref.Val {
		// Handle nil registry (validation mode)
		if registry == nil {
			return types.NullValue
		}

		query, ok := arg.Value().(string)
		if !ok {
			return types.NewErr("dns.getResponse: argument must be string")
		}

		dnsStore := registry.DNS()
		if dnsStore == nil {
			return types.NullValue
		}

		response, err := dnsStore.GetDNSResponse(query)
		if err != nil {
			if errors.Is(err, datastores.ErrNotFound) {
				return types.NullValue
			}
			return types.NewErr("dns.getResponse: %v", err)
		}

		return convertDNSResponseToCEL(response)
	}
}

// SyscallStore bindings

func createSyscallGetNameBinding(registry datastores.Registry) func(ref.Val) ref.Val {
	return func(arg ref.Val) ref.Val {
		// Handle nil registry (validation mode)
		if registry == nil {
			return types.String("")
		}

		syscallId, ok := arg.Value().(int64)
		if !ok {
			return types.NewErr("syscall.getName: argument must be int")
		}

		syscallStore := registry.Syscalls()
		if syscallStore == nil {
			return types.String("")
		}

		name, err := syscallStore.GetSyscallName(int32(syscallId))
		if err != nil {
			if errors.Is(err, datastores.ErrNotFound) {
				return types.String("")
			}
			return types.NewErr("syscall.getName: %v", err)
		}

		return types.String(name)
	}
}

func createSyscallGetIdBinding(registry datastores.Registry) func(ref.Val) ref.Val {
	return func(arg ref.Val) ref.Val {
		// Handle nil registry (validation mode)
		if registry == nil {
			return types.Int(-1)
		}

		syscallName, ok := arg.Value().(string)
		if !ok {
			return types.NewErr("syscall.getId: argument must be string")
		}

		syscallStore := registry.Syscalls()
		if syscallStore == nil {
			return types.Int(-1)
		}

		id, err := syscallStore.GetSyscallID(syscallName)
		if err != nil {
			if errors.Is(err, datastores.ErrNotFound) {
				return types.Int(-1)
			}
			return types.NewErr("syscall.getId: %v", err)
		}

		return types.Int(id)
	}
}

// Conversion helpers (convert datastore types to CEL values)

func convertProcessInfoToCEL(p *datastores.ProcessInfo) ref.Val {
	return types.DefaultTypeAdapter.NativeToValue(map[string]any{
		"entity_id":  p.UniqueId,
		"pid":        p.Pid,
		"ppid":       p.Ppid,
		"name":       p.Name,
		"exe":        p.Exe,
		"start_time": p.StartTime.Unix(),
		"uid":        p.UID,
		"gid":        p.GID,
	})
}

func convertProcessListToCEL(procs []*datastores.ProcessInfo) ref.Val {
	procList := make([]any, len(procs))
	for i, p := range procs {
		procList[i] = map[string]any{
			"entity_id":  p.UniqueId,
			"pid":        p.Pid,
			"ppid":       p.Ppid,
			"name":       p.Name,
			"exe":        p.Exe,
			"start_time": p.StartTime.Unix(),
			"uid":        p.UID,
			"gid":        p.GID,
		}
	}
	return types.DefaultTypeAdapter.NativeToValue(procList)
}

func convertContainerInfoToCEL(c *datastores.ContainerInfo) ref.Val {
	data := map[string]any{
		"id":           c.ID,
		"name":         c.Name,
		"image":        c.Image,
		"image_digest": c.ImageDigest,
		"runtime":      c.Runtime,
		"start_time":   c.StartTime.Unix(),
	}
	if c.Pod != nil {
		data["pod"] = map[string]any{
			"name":      c.Pod.Name,
			"uid":       c.Pod.UID,
			"namespace": c.Pod.Namespace,
			"sandbox":   c.Pod.Sandbox,
		}
	} else {
		data["pod"] = nil
	}
	return types.DefaultTypeAdapter.NativeToValue(data)
}

func convertSystemInfoToCEL(s *datastores.SystemInfo) ref.Val {
	return types.DefaultTypeAdapter.NativeToValue(map[string]any{
		"architecture":      s.Architecture,
		"kernel_release":    s.KernelRelease,
		"hostname":          s.Hostname,
		"boot_time":         s.BootTime.Unix(),
		"tracee_start_time": s.TraceeStartTime.Unix(),
		"os_name":           s.OSName,
		"os_version":        s.OSVersion,
		"os_pretty_name":    s.OSPrettyName,
		"tracee_version":    s.TraceeVersion,
	})
}

func convertSymbolListToCEL(symbols []*datastores.SymbolInfo) ref.Val {
	symbolList := make([]any, len(symbols))
	for i, s := range symbols {
		symbolList[i] = map[string]any{
			"name":    s.Name,
			"address": s.Address,
			"module":  s.Module,
		}
	}
	return types.DefaultTypeAdapter.NativeToValue(symbolList)
}

func convertDNSResponseToCEL(r *datastores.DNSResponse) ref.Val {
	return types.DefaultTypeAdapter.NativeToValue(map[string]any{
		"query":   r.Query,
		"ips":     r.IPs,
		"domains": r.Domains,
	})
}
