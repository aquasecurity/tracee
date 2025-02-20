package filters

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	"golang.org/x/exp/maps"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/utils"
	"github.com/aquasecurity/tracee/types/trace"
)

const (
	maxBpfDataFilterStrSize = 256 // maximum str size supported by Data filter in BPF (MAX_DATA_FILTER_STR_SIZE)
)

// KernelDataFilter manages the state of data field filters,
// indicating whether each filter is enabled or disabled in the kernel.
type KernelDataFilter struct {
	kernelFilters map[string]bool
}

func NewKernelDataFilter() *KernelDataFilter {
	return &KernelDataFilter{
		kernelFilters: make(map[string]bool),
	}
}

// enableKernelFilter enables kernel data field filter for the specified field.
func (kdf *KernelDataFilter) enableKernelFilter(field string) {
	kdf.kernelFilters[field] = true
}

// IsKernelFilterEnabled checks if kernel data field filter is enabled for the specified field.
func (kdf *KernelDataFilter) IsKernelFilterEnabled(field string) bool {
	if ok := kdf.kernelFilters[field]; ok {
		return true
	}
	return false
}

// getKernelFieldName return only one field name with in-kernel filter
// TODO: need to retrieve all possible field names (and not only one)
func (kdf *KernelDataFilter) getKernelFieldName() string {
	var key string
	for k := range kdf.kernelFilters {
		key = k
		break
	}
	return key
}

type DataFilter struct {
	filters          map[string]Filter[*StringFilter]
	kernelDataFilter *KernelDataFilter
	enabled          bool
}

// Compile-time check to ensure that DataFilter implements the Cloner interface.
var _ utils.Cloner[*DataFilter] = &DataFilter{}

func NewDataFilter() *DataFilter {
	return &DataFilter{
		filters:          map[string]Filter[*StringFilter]{},
		kernelDataFilter: NewKernelDataFilter(),
		enabled:          false,
	}
}

// list of events and field names allowed to have in-kernel filter
var allowedKernelField = map[events.ID]string{
	// LSM hooks
	events.SecurityBprmCheck:           "pathname",  // index: 0
	events.SecurityFileOpen:            "pathname",  // 0
	events.SecurityInodeUnlink:         "pathname",  // 0
	events.SecuritySbMount:             "path",      // 1
	events.SecurityBPFMap:              "map_name",  // 1
	events.SecurityKernelReadFile:      "pathname",  // 0
	events.SecurityInodeMknod:          "file_name", // 0
	events.SecurityPostReadFile:        "pathname",  // 0
	events.SecurityInodeSymlinkEventId: "linkpath",  // 0
	events.SecurityMmapFile:            "pathname",  // 0
	events.SecurityFileMprotect:        "pathname",  // 0
	events.SecurityInodeRename:         "old_path",  // 0
	events.SecurityBpfProg:             "name",      // 1
	events.SecurityPathNotify:          "pathname",  // 0
	events.SharedObjectLoaded:          "pathname",  // 0

	// Others
	events.SchedProcessExec:   "pathname",         // 1
	events.VfsWrite:           "pathname",         // 0
	events.VfsWritev:          "pathname",         // 0
	events.VfsRead:            "pathname",         // 0
	events.VfsReadv:           "pathname",         // 0
	events.MemProtAlert:       "pathname",         // 5
	events.MagicWrite:         "pathname",         // 0
	events.KernelWrite:        "pathname",         // 0
	events.CallUsermodeHelper: "pathname",         // 0
	events.LoadElfPhdrs:       "pathname",         // 0
	events.DoMmap:             "pathname",         // 1
	events.VfsUtimes:          "pathname",         // 0
	events.DoTruncate:         "pathname",         // 0
	events.InotifyWatch:       "pathname",         // 0
	events.ModuleLoad:         "pathname",         // 3
	events.ChmodCommon:        "pathname",         // 0
	events.DeviceAdd:          "name",             // 0
	events.DoInitModule:       "name",             // 0
	events.ModuleFree:         "name",             // 0
	events.ProcCreate:         "name",             // 0
	events.RegisterChrdev:     "char_device_name", // 2
	events.DebugfsCreateFile:  "file_name",        // 0
	events.DebugfsCreateDir:   "name",             // 0
	events.CgroupMkdir:        "cgroup_path",      // 1
	events.CgroupRmdir:        "cgroup_path",      // 1
	events.CgroupAttachTask:   "cgroup_path",      // 0
	events.BpfAttach:          "prog_name",        // 1
	events.KprobeAttach:       "symbol_name",      // 0
	events.TaskRename:         "old_name",         // 0
	events.FileModification:   "file_path",        // 0
	events.SetFsPwd:           "resolved_path",    // 1
	events.SchedSwitch:        "prev_comm",        // 2
	events.HiddenInodes:       "hidden_process",   // 0
	events.DirtyPipeSplice:    "in_file_path",     // 2

	// Syscalls
	events.Execve:   "pathname",
	events.Execveat: "pathname",
}

// checkAvailabilityKernelFilter check if event ID and field name are allowed to be an kernel filter
func (f *DataFilter) checkAvailabilityKernelFilter(event events.ID, field string) bool {
	if selectedField := allowedKernelField[event]; selectedField != field {
		return false
	}

	return true
}

func (f *DataFilter) Equalities() (StringFilterEqualities, error) {
	if !f.Enabled() {
		return StringFilterEqualities{
			ExactEqual:     map[string]struct{}{},
			ExactNotEqual:  map[string]struct{}{},
			PrefixEqual:    map[string]struct{}{},
			PrefixNotEqual: map[string]struct{}{},
			SuffixEqual:    map[string]struct{}{},
			SuffixNotEqual: map[string]struct{}{},
		}, nil
	}

	// get the field name for in-kernel filter
	// TODO: only one allowed at the moment (more to come)
	dataField := f.kernelDataFilter.getKernelFieldName()

	fieldName, ok := f.filters[dataField]
	if !ok {
		return StringFilterEqualities{}, fmt.Errorf("field %s does not exist in filters", dataField)
	}

	filter, ok := fieldName.(*StringFilter)
	if !ok {
		return StringFilterEqualities{}, fmt.Errorf("failed to assert field %s as *StringFilter", dataField)
	}

	equalities := filter.Equalities()

	return StringFilterEqualities{
		ExactEqual:     maps.Clone(equalities.ExactEqual),
		ExactNotEqual:  maps.Clone(equalities.ExactNotEqual),
		PrefixEqual:    maps.Clone(equalities.PrefixEqual),
		PrefixNotEqual: maps.Clone(equalities.PrefixNotEqual),
		SuffixEqual:    maps.Clone(equalities.SuffixEqual),
		SuffixNotEqual: maps.Clone(equalities.SuffixNotEqual),
	}, nil
}

// GetFieldFilters returns the data filters map
// writing to the map may have unintentional consequences, avoid doing so
// TODO: encapsulate by replacing this function with "GetFieldFilter(fieldName string) StringFilter"
func (f *DataFilter) GetFieldFilters() map[string]Filter[*StringFilter] {
	return f.filters
}

func (f *DataFilter) Filter(data []trace.Argument) bool {
	if !f.Enabled() {
		return true
	}

	for fieldName, filter := range f.filters {
		found := false
		var fieldVal interface{}

		// No need to filter the following field name as they have already
		// been filtered in the kernel space
		// TODO: Rethink whether using an integer instead of a string
		// would improve efficiency in the args structure.
		if f.kernelDataFilter.IsKernelFilterEnabled(fieldName) {
			continue
		}

		for _, field := range data {
			if field.Name == fieldName {
				found = true
				fieldVal = field.Value
				break
			}
		}
		if !found {
			return false
		}

		// TODO: use type assertion instead of string conversion
		fieldVal = fmt.Sprint(fieldVal)

		res := filter.Filter(fieldVal)
		if !res {
			return false
		}
	}

	return true
}

func (f *DataFilter) Parse(id events.ID, fieldName string, operatorAndValues string) error {
	eventDefinition := events.Core.GetDefinitionByID(id)
	eventFields := eventDefinition.GetFields()

	// check if data field name exists for this event
	fieldFound := false
	for i := range eventFields {
		if eventFields[i].Name == fieldName {
			fieldFound = true
			break
		}
	}

	// if the event is a signature event, we allow filtering on dynamic argument
	if !fieldFound && !eventDefinition.IsSignature() {
		return InvalidEventField(fieldName)
	}

	// valueHandler is passed to the filter constructor to allow for custom value handling
	// before the filter is applied
	valueHandler := func(val string) (string, error) {
		if f.checkAvailabilityKernelFilter(id, fieldName) {
			return f.processKernelFilter(val, fieldName)
		}
		switch id {
		case events.SysEnter,
			events.SysExit,
			events.SuspiciousSyscallSource,
			events.StackPivot:
			if fieldName == "syscall" { // handle either syscall name or syscall id
				_, err := strconv.Atoi(val)
				if err == nil {
					return val, nil // val might already be a syscall id
				}

				// val might be a syscall name, then we need to convert it to a syscall id
				syscallID, ok := events.Core.GetDefinitionIDByName(val)
				if !ok {
					return val, errfmt.Errorf("invalid syscall name: %s", val)
				}
				val = strconv.Itoa(int(syscallID))
			}

		case events.HookedSyscall:
			if fieldName == "syscall" { // handle either syscall name or syscall id
				dataEventID, err := strconv.Atoi(val)
				// check if dataEventID is a syscall id
				if err != nil {
					return val, nil // val might already be a syscall name
				}
				if dataEventID < 0 || dataEventID > math.MaxInt32 {
					return val, errfmt.Errorf("invalid syscall id: %s", val)
				}

				// val might be a syscall id, then we need to convert it to a syscall name
				val = events.Core.GetDefinitionByID(events.ID(dataEventID)).GetName()
			}
		}

		return val, nil
	}

	err := f.parseFilter(fieldName, operatorAndValues,
		func() Filter[*StringFilter] {
			// TODO: map data type to an appropriate filter constructor
			return NewStringFilter(valueHandler)
		})
	if err != nil {
		return errfmt.WrapError(err)
	}

	f.Enable()

	return nil
}

// parseFilter adds an data filter with the relevant filterConstructor.
// The user must responsibly supply a reliable Filter object.
func (f *DataFilter) parseFilter(fieldName string, operatorAndValues string, filterConstructor func() Filter[*StringFilter]) error {
	if _, ok := f.filters[fieldName]; !ok {
		// store new event data filter if missing
		dataFilter := filterConstructor()
		f.filters[fieldName] = dataFilter
	}

	err := f.filters[fieldName].Parse(operatorAndValues)
	if err != nil {
		return errfmt.WrapError(err)
	}

	return nil
}

func (f *DataFilter) processKernelFilter(val, fieldName string) (string, error) {
	// Check for kernel filter restrictions
	if err := f.checkKernelFilterRestrictions(val); err != nil {
		return val, err
	}

	// Enable the kernel filter if restrictions are satisfied
	f.enableKernelFilterArg(fieldName)
	return val, nil
}

// checkKernelFilterRestrictions enforces restrictions for kernel-filtered fields:
// 1) Values cannot use "contains" (e.g., start and end with "*").
// 2) Maximum length for the value is 255 characters.
func (f *DataFilter) checkKernelFilterRestrictions(val string) error {
	if len(val) == 0 {
		return InvalidValue("empty value is not allowed")
	}

	// Disallow "*" and "**" as invalid values
	if val == "*" || val == "**" {
		return InvalidValue(val)
	}

	// Check for "contains" type filtering
	if len(val) > 1 && val[0] == '*' && val[len(val)-1] == '*' {
		return InvalidFilterType()
	}

	// Enforce maximum length restriction
	trimmedVal := strings.Trim(val, "*")
	if len(trimmedVal) > maxBpfDataFilterStrSize-1 {
		return InvalidValueMax(val, maxBpfDataFilterStrSize-1)
	}
	return nil
}

// enableKernelFilterArg activates a kernel filter for the specified data field.
// This function currently supports enabling filters for the "pathname" field only.
func (f *DataFilter) enableKernelFilterArg(fieldName string) {
	filter, ok := f.filters[fieldName]
	if !ok {
		return
	}

	strFilter, ok := filter.(*StringFilter)
	if !ok {
		logger.Debugw("Failed to assert", "fieldName", fieldName)
		return
	}

	strFilter.Enable()
	f.kernelDataFilter.enableKernelFilter(fieldName)
}

func (f *DataFilter) Enable() {
	f.enabled = true
	for _, filter := range f.filters {
		filter.Enable()
	}
}

func (f *DataFilter) Disable() {
	f.enabled = false
	for _, filter := range f.filters {
		filter.Disable()
	}
}

func (f *DataFilter) Enabled() bool {
	return f.enabled
}

func (f *DataFilter) Clone() *DataFilter {
	if f == nil {
		return nil
	}

	n := NewDataFilter()

	for fieldName, filter := range f.filters {
		n.filters[fieldName] = filter.Clone()
	}

	n.enabled = f.enabled

	return n
}
