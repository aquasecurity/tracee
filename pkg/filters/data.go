package filters

import (
	"fmt"
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

	// selected data name
	dataField := "pathname"

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
		switch id {
		case events.SecurityFileOpen,
			events.MagicWrite,
			events.SecurityMmapFile:
			return f.processKernelFilter(val, fieldName)

		case events.SysEnter,
			events.SysExit,
			events.SuspiciousSyscallSource,
			events.StackPivot:
			if fieldName == "syscall" { // handle either syscall name or syscall id
				_, err := strconv.Atoi(val)
				if err != nil {
					// if val is a syscall name, then we need to convert it to a syscall id
					syscallID, ok := events.Core.GetDefinitionIDByName(val)
					if !ok {
						return val, errfmt.Errorf("invalid syscall name: %s", val)
					}
					val = strconv.Itoa(int(syscallID))
				}
			}
		case events.HookedSyscall:
			if fieldName == "syscall" { // handle either syscall name or syscall id
				dataEventID, err := strconv.Atoi(val)
				if err == nil {
					// if val is a syscall id, then we need to convert it to a syscall name
					val = events.Core.GetDefinitionByID(events.ID(dataEventID)).GetName()
				}
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
	if fieldName != "pathname" {
		return
	}

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
