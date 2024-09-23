package filters

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/utils"
	"github.com/aquasecurity/tracee/types/trace"
)

type MatchTypes struct {
	exactlyMatch    bool
	notExactlyMatch bool
	prefixMatch     bool
	notPrefixMatch  bool
	suffixMatch     bool
	notSuffixMatch  bool
}

type DataFilter struct {
	filters       map[events.ID]map[string]Filter[*StringFilter]
	enabled       bool
	enabledKernel MatchTypes
}

// Compile-time check to ensure that DataFilter implements the Cloner interface
var _ utils.Cloner[*DataFilter] = &DataFilter{}

func NewDataFilter() *DataFilter {
	return &DataFilter{
		filters: map[events.ID]map[string]Filter[*StringFilter]{},
		enabled: false,
		enabledKernel: MatchTypes{
			exactlyMatch:    false,
			notExactlyMatch: false,
			prefixMatch:     false,
			notPrefixMatch:  false,
			suffixMatch:     false,
			notSuffixMatch:  false,
		},
	}
}

type KernelData struct {
	ID   events.ID
	Path string
}

type DataFilterEqualities struct {
	Equal          map[KernelData]struct{}
	NotEqual       map[KernelData]struct{}
	EqualPrefix    map[KernelData]struct{}
	NotEqualPrefix map[KernelData]struct{}
	EqualSuffix    map[KernelData]struct{}
	NotEqualSuffix map[KernelData]struct{}
}

func (af *DataFilter) Equalities() DataFilterEqualities {
	if !af.Enabled() {
		return DataFilterEqualities{
			Equal:          map[KernelData]struct{}{},
			NotEqual:       map[KernelData]struct{}{},
			EqualPrefix:    map[KernelData]struct{}{},
			NotEqualPrefix: map[KernelData]struct{}{},
			EqualSuffix:    map[KernelData]struct{}{},
			NotEqualSuffix: map[KernelData]struct{}{},
		}
	}

	combinedEqualities := make(map[KernelData]struct{})
	combinedNotEqualities := make(map[KernelData]struct{})
	combinedPrefixEqualities := make(map[KernelData]struct{})
	combinedNotPrefixEqualities := make(map[KernelData]struct{})
	combinedSuffixEqualities := make(map[KernelData]struct{})
	combinedNotSuffixEqualities := make(map[KernelData]struct{})

	// selected events
	eventIDs := []events.ID{events.SecurityFileOpen, events.MagicWrite, events.SecurityMmapFile}

	// selected data name
	dataField := "pathname"

	for _, eventID := range eventIDs {
		if filterMap, ok := af.filters[eventID]; ok {
			if pathName, ok := filterMap[dataField]; ok {
				if filter, ok := pathName.(*StringFilter); ok {
					// Merge the equalities and not-equalities into the combined maps
					// Exactly match
					for k := range filter.Equalities().Equal {
						combinedEqualities[KernelData{eventID, k}] = struct{}{}
						af.enabledKernel.exactlyMatch = true
					}
					for k := range filter.Equalities().NotEqual {
						combinedNotEqualities[KernelData{eventID, k}] = struct{}{}
						af.enabledKernel.notExactlyMatch = true
						af.enabledKernel.exactlyMatch = true
					}

					// Prefix match
					for k := range filter.Equalities().EqualPrefix {
						combinedPrefixEqualities[KernelData{eventID, k}] = struct{}{}
						af.enabledKernel.prefixMatch = true
					}
					for k := range filter.Equalities().NotEqualPrefix {
						combinedNotPrefixEqualities[KernelData{eventID, k}] = struct{}{}
						af.enabledKernel.notPrefixMatch = true
						af.enabledKernel.prefixMatch = true
					}

					// Suffix match
					for k := range filter.Equalities().EqualSuffix {
						reversed := utils.ReverseString(k)
						combinedSuffixEqualities[KernelData{eventID, reversed}] = struct{}{}
						af.enabledKernel.suffixMatch = true
					}
					for k := range filter.Equalities().NotEqualSuffix {
						reversed := utils.ReverseString(k)
						combinedNotSuffixEqualities[KernelData{eventID, reversed}] = struct{}{}
						af.enabledKernel.notSuffixMatch = true
						af.enabledKernel.suffixMatch = true
					}
				}
			}
		}
	}

	return DataFilterEqualities{
		Equal:          combinedEqualities,
		NotEqual:       combinedNotEqualities,
		EqualPrefix:    combinedPrefixEqualities,
		NotEqualPrefix: combinedNotPrefixEqualities,
		EqualSuffix:    combinedSuffixEqualities,
		NotEqualSuffix: combinedNotSuffixEqualities,
	}
}

// GetEventFilters returns the data filters map for a specific event
// writing to the map may have unintentional consequences, avoid doing so
func (af *DataFilter) GetEventFilters(eventID events.ID) map[string]Filter[*StringFilter] {
	return af.filters[eventID]
}

func (af *DataFilter) Filter(eventID events.ID, data []trace.Argument) bool {
	if !af.Enabled() {
		return true
	}

	// don't Filter this special case
	if eventID == events.SecurityFileOpen || eventID == events.MagicWrite || eventID == events.SecurityMmapFile {
		if filterMap, ok := af.filters[eventID]; ok {
			if pathName, ok := filterMap["pathname"]; ok {
				if _, ok := pathName.(*StringFilter); ok {
					return true
				}
			}
		}
	}

	// TODO: remove once events params are introduced
	//       i.e. print_mem_dump.params.symbol_name=system:security_file_open
	// events.PrintMemDump bypass was added due to issue #2546
	// because it uses usermode applied filters as parameters for the event,
	// which occurs after filtering
	if eventID == events.PrintMemDump {
		return true
	}

	for dataName, f := range af.filters[eventID] {
		found := false
		var dataVal interface{}

		for _, d := range data {
			if d.Name == dataName {
				found = true
				dataVal = d.Value
				break
			}
		}
		if !found {
			return false
		}

		// TODO: use type assertion instead of string conversion
		dataVal = fmt.Sprint(dataVal)

		res := f.Filter(dataVal)
		if !res {
			return false
		}
	}

	return true
}

func (af *DataFilter) Parse(filterName string, operatorAndValues string, eventsNameToID map[string]events.ID) error {
	// Event data filter has the following format: "event.data.dataname=dataval"
	// filterName have the format event.dataname, and operatorAndValues have the format "=dataval"
	parts := strings.Split(filterName, ".")
	if len(parts) != 3 {
		return InvalidExpression(filterName + operatorAndValues)
	}
	// option "args" will be deprecate in future
	if (parts[1] != "data") && (parts[1] != "args") {
		return InvalidExpression(filterName + operatorAndValues)
	}

	eventName := parts[0]
	dataName := parts[2]

	if eventName == "" || dataName == "" {
		return InvalidExpression(filterName + operatorAndValues)
	}

	id, ok := eventsNameToID[eventName]
	if !ok {
		return InvalidEventName(eventName)
	}

	if !events.Core.IsDefined(id) {
		return InvalidEventName(eventName)
	}
	eventDefinition := events.Core.GetDefinitionByID(id)
	eventParams := eventDefinition.GetParams()

	// check if data name exists for this event
	dataFound := false
	for i := range eventParams {
		if eventParams[i].Name == dataName {
			dataFound = true
			break
		}
	}

	// if the event is a signature event, we allow filtering on dynamic argument
	if !dataFound && !eventDefinition.IsSignature() {
		return InvalidEventData(dataName)
	}

	// valueHandler is passed to the filter constructor to allow for custom value handling
	// before the filter is applied
	valueHandler := func(val string) (string, error) {
		switch id {
		case events.SecurityFileOpen,
			events.MagicWrite,
			events.SecurityMmapFile:
			if dataName == "pathname" {
				af.EnableKernel()
			}
		case events.SysEnter,
			events.SysExit:
			if dataName == "syscall" { // handle either syscall name or syscall id
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
			if dataName == "syscall" { // handle either syscall name or syscall id
				dataEventID, err := strconv.Atoi(val)
				if err == nil {
					// if val is a syscall id, then we need to convert it to a syscall name
					val = events.Core.GetDefinitionByID(events.ID(dataEventID)).GetName()
				}
			}
		}

		return val, nil
	}

	err := af.parseFilter(id, dataName, operatorAndValues,
		func() Filter[*StringFilter] {
			// TODO: map data type to an appropriate filter constructor
			return NewStringFilter(valueHandler)
		})
	if err != nil {
		return errfmt.WrapError(err)
	}

	af.Enable()

	return nil
}

// parseFilter adds an data filter with the relevant filterConstructor
// The user must responsibly supply a reliable Filter object.
func (af *DataFilter) parseFilter(id events.ID, dataName string, operatorAndValues string, filterConstructor func() Filter[*StringFilter]) error {
	if _, ok := af.filters[id]; !ok {
		af.filters[id] = map[string]Filter[*StringFilter]{}
	}

	if _, ok := af.filters[id][dataName]; !ok {
		// store new event data filter if missing
		dataFilter := filterConstructor()
		af.filters[id][dataName] = dataFilter
	}

	// extract the data filter and parse expression into it
	f := af.filters[id][dataName]
	err := f.Parse(operatorAndValues)
	if err != nil {
		return errfmt.WrapError(err)
	}

	// store the data filter again
	af.filters[id][dataName] = f

	return nil
}

func (af *DataFilter) Enable() {
	af.enabled = true
	for _, filterMap := range af.filters {
		for _, f := range filterMap {
			f.Enable()
		}
	}
}

func (af *DataFilter) EnableKernel() {
	// af.enabledKernel = true
	for eventId, filterMap := range af.filters {
		if eventId == events.SecurityFileOpen ||
			eventId == events.MagicWrite || eventId == events.SecurityMmapFile {
			if pathName, ok := filterMap["pathname"]; ok {
				if strFilter, ok := pathName.(*StringFilter); ok {
					strFilter.Enable()
				}
			}
		}
	}
}

func (af *DataFilter) Disable() {
	af.enabled = false
	for _, filterMap := range af.filters {
		for _, f := range filterMap {
			f.Disable()
		}
	}
}

func (af *DataFilter) Enabled() bool {
	return af.enabled
}

func (af *DataFilter) EnabledExcatlyMatch() bool {
	return af.enabledKernel.exactlyMatch
}

func (af *DataFilter) EnabledPrefixMatch() bool {
	return af.enabledKernel.prefixMatch
}

func (af *DataFilter) EnabledSuffixMatch() bool {
	return af.enabledKernel.suffixMatch
}

func (af *DataFilter) FilterOutExcatlyMatch() bool {
	return af.enabledKernel.notExactlyMatch
}

func (af *DataFilter) FilterOutPrefixMatch() bool {
	return af.enabledKernel.notPrefixMatch
}

func (af *DataFilter) FilterOutSuffixMatch() bool {
	return af.enabledKernel.notSuffixMatch
}

func (af *DataFilter) Clone() *DataFilter {
	if af == nil {
		return nil
	}

	n := NewDataFilter()

	for eventID, filterMap := range af.filters {
		n.filters[eventID] = map[string]Filter[*StringFilter]{}
		for dataName, f := range filterMap {
			n.filters[eventID][dataName] = f.Clone()
		}
	}

	n.enabled = af.enabled

	return n
}
