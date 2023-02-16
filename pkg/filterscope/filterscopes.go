package filterscope

import (
	"sync/atomic"

	"github.com/aquasecurity/tracee/pkg/filters"
	"github.com/aquasecurity/tracee/pkg/utils"
)

// TODO: add locking mechanism as scopes will change at runtime
type FilterScopes struct {
	filterScopesArray        [MaxFilterScopes]*FilterScope // underlying filter scopes array
	filterEnabledScopesMap   map[*FilterScope]int          // stores only enabled scopes
	filterUserSpaceScopesMap map[*FilterScope]int          // stores a reduced map with only user space filtered scopes

	uidFilterMin             uint64
	uidFilterMax             uint64
	pidFilterMin             uint64
	pidFilterMax             uint64
	uidFilterableInUserSpace bool
	pidFilterableInUserSpace bool

	containerFiltersEnabled uint64
}

func NewFilterScopes() *FilterScopes {
	return &FilterScopes{
		filterScopesArray:        [MaxFilterScopes]*FilterScope{},
		filterEnabledScopesMap:   map[*FilterScope]int{},
		filterUserSpaceScopesMap: map[*FilterScope]int{},
		uidFilterMin:             filters.MinNotSetUInt,
		uidFilterMax:             filters.MaxNotSetUInt,
		pidFilterMin:             filters.MinNotSetUInt,
		pidFilterMax:             filters.MaxNotSetUInt,
		uidFilterableInUserSpace: false,
		pidFilterableInUserSpace: false,
		containerFiltersEnabled:  0,
	}
}

func (fs *FilterScopes) Count() int {
	return len(fs.filterEnabledScopesMap)
}

func (fs *FilterScopes) UIDFilterMin() uint64 {
	return fs.uidFilterMin
}

func (fs *FilterScopes) UIDFilterMax() uint64 {
	return fs.uidFilterMax
}

func (fs *FilterScopes) PIDFilterMin() uint64 {
	return fs.pidFilterMin
}

func (fs *FilterScopes) PIDFilterMax() uint64 {
	return fs.pidFilterMax
}

func (fs *FilterScopes) UIDFilterableInUserSpace() bool {
	return fs.uidFilterableInUserSpace
}

func (fs *FilterScopes) PIDFilterableInUserSpace() bool {
	return fs.pidFilterableInUserSpace
}

// ContainerFilterEnabled returns a bitmask of scopes that have at least one
// container filter type enabled
func (fs *FilterScopes) ContainerFilterEnabled() uint64 {
	return atomic.LoadUint64(&fs.containerFiltersEnabled)
}

// Compute recalculates values, updates flags and fills the reduced user space
// map. It must be called at initialization and at every runtime scopes changes
func (fs *FilterScopes) Compute() {
	// update global min and max
	fs.calculateGlobalMinMax()

	// update enabled container filter flag
	fs.updateContainerFilterEnabled()

	userSpaceMap := make(map[*FilterScope]int)

	for filterScope := range fs.filterEnabledScopesMap {
		if filterScope.ArgFilter.Enabled() ||
			filterScope.RetFilter.Enabled() ||
			filterScope.ContextFilter.Enabled() ||
			(filterScope.UIDFilter.Enabled() && fs.UIDFilterableInUserSpace()) ||
			(filterScope.PIDFilter.Enabled() && fs.PIDFilterableInUserSpace()) {

			userSpaceMap[filterScope] = filterScope.ID
		}
	}

	fs.filterUserSpaceScopesMap = userSpaceMap
}

// set, if not err, always reassign values
func (fs *FilterScopes) set(id int, scope *FilterScope) error {
	if scope == nil {
		return FilterScopeNilError()
	}
	if !isIDInRange(id) {
		return FilterScopesOutOfRangeError(id)
	}
	if _, found := fs.filterEnabledScopesMap[scope]; found {
		if scope.ID != id {
			return FilterScopeAlreadyExists(scope, id)
		}
	}

	scope.ID = id
	fs.filterScopesArray[id] = scope
	fs.filterEnabledScopesMap[scope] = id

	fs.Compute()

	return nil
}

// Add adds a scope to FilterScopes.
// Its ID (index) is set to the first room found.
// Returns nil if scope is already inserted.
func (fs *FilterScopes) Add(scope *FilterScope) error {
	if len(fs.filterEnabledScopesMap) == MaxFilterScopes {
		return FilterScopesMaxExceededError()
	}

	for id := range fs.filterScopesArray {
		if fs.filterScopesArray[id] == nil {
			return fs.set(id, scope)
		}
	}

	return nil
}

func (fs *FilterScopes) Set(id int, scope *FilterScope) error {
	return fs.set(id, scope)
}

// Delete deletes a scope from FilterScopes.
func (fs *FilterScopes) Delete(id int) error {
	if !isIDInRange(id) {
		return FilterScopesOutOfRangeError(id)
	}
	if len(fs.filterEnabledScopesMap) == 0 {
		return nil
	}

	delete(fs.filterEnabledScopesMap, fs.filterScopesArray[id])
	delete(fs.filterUserSpaceScopesMap, fs.filterScopesArray[id])
	fs.filterScopesArray[id] = nil

	fs.Compute()

	return nil
}

func (fs *FilterScopes) Lookup(id int) (*FilterScope, error) {
	if !isIDInRange(id) {
		return nil, FilterScopesOutOfRangeError(id)
	}

	scope := fs.filterScopesArray[id]
	if scope == nil {
		return nil, FilterScopeNotFoundError(id)
	}
	return scope, nil
}

func (fs *FilterScopes) Map() map[*FilterScope]int {
	return fs.filterEnabledScopesMap
}

func (fs *FilterScopes) updateContainerFilterEnabled() {
	fs.containerFiltersEnabled = 0

	for filterScope := range fs.Map() {
		if filterScope.ContainerFilterEnabled() {
			utils.SetBit(&fs.containerFiltersEnabled, uint(filterScope.ID))
		}
	}
}

// UserSpaceMap returns a reduced scopes map which must be filtered in
// user space (ArgFilter, RetFilter, ContextFilter, UIDFilter and PIDFilter).
func (fs *FilterScopes) UserSpaceMap() map[*FilterScope]int {
	return fs.filterUserSpaceScopesMap
}

// calculateGlobalMinMax sets the global min and max, to be checked in kernel
// space, of the Minimum and Maximum enabled filters only if context filter
// types (e.g. BPFUIDFilter) from all scopes have both Minimum and Maximum
// values set.
//
// FilterScopes user space filter flags are also set (e.g.
// uidFilterableInUserSpace).
//
// The context filter types relevant for this function are just UIDFilter and
// PIDFilter.
func (fs *FilterScopes) calculateGlobalMinMax() {
	var (
		uidMinFilterCount int
		uidMaxFilterCount int
		uidFilterCount    int
		pidMinFilterCount int
		pidMaxFilterCount int
		pidFilterCount    int
		scopeCount        int

		uidMinFilterableInUserSpace bool
		uidMaxFilterableInUserSpace bool
		pidMinFilterableInUserSpace bool
		pidMaxFilterableInUserSpace bool
	)

	for filterScope := range fs.Map() {
		scopeCount++

		if filterScope.UIDFilter.Enabled() {
			uidFilterCount++

			if filterScope.UIDFilter.Minimum() != filters.MinNotSetUInt {
				uidMinFilterCount++
			}
			if filterScope.UIDFilter.Maximum() != filters.MaxNotSetUInt {
				uidMaxFilterCount++
			}
		}
		if filterScope.PIDFilter.Enabled() {
			pidFilterCount++

			if filterScope.PIDFilter.Minimum() != filters.MinNotSetUInt {
				pidMinFilterCount++
			}
			if filterScope.PIDFilter.Maximum() != filters.MaxNotSetUInt {
				pidMaxFilterCount++
			}
		}
	}

	uidMinFilterableInUserSpace = scopeCount > 1 && (uidMinFilterCount != uidFilterCount)
	uidMaxFilterableInUserSpace = scopeCount > 1 && (uidMaxFilterCount != uidFilterCount)
	pidMinFilterableInUserSpace = scopeCount > 1 && (pidMinFilterCount != pidFilterCount)
	pidMaxFilterableInUserSpace = scopeCount > 1 && (pidMaxFilterCount != pidFilterCount)

	// reset global min max
	fs.uidFilterMax = filters.MaxNotSetUInt
	fs.uidFilterMin = filters.MinNotSetUInt
	fs.pidFilterMax = filters.MaxNotSetUInt
	fs.pidFilterMin = filters.MinNotSetUInt

	fs.uidFilterableInUserSpace = uidMinFilterableInUserSpace || uidMaxFilterableInUserSpace
	fs.pidFilterableInUserSpace = pidMinFilterableInUserSpace || pidMaxFilterableInUserSpace

	if fs.UIDFilterableInUserSpace() && fs.PIDFilterableInUserSpace() {
		// there's no need to iterate filter scopes again since
		// all uint events will be submitted from ebpf with no regards

		return
	}

	// set a reduced range of uint values to be filtered in ebpf
	for filterScope := range fs.filterEnabledScopesMap {
		if filterScope.UIDFilter.Enabled() {
			if !uidMinFilterableInUserSpace {
				fs.uidFilterMin = utils.Min(fs.uidFilterMin, filterScope.UIDFilter.Minimum())
			}
			if !uidMaxFilterableInUserSpace {
				fs.uidFilterMax = utils.Max(fs.uidFilterMax, filterScope.UIDFilter.Maximum())
			}
		}
		if filterScope.PIDFilter.Enabled() {
			if !pidMinFilterableInUserSpace {
				fs.pidFilterMin = utils.Min(fs.pidFilterMin, filterScope.PIDFilter.Minimum())
			}
			if !pidMaxFilterableInUserSpace {
				fs.pidFilterMax = utils.Max(fs.pidFilterMax, filterScope.PIDFilter.Maximum())
			}
		}
	}
}

// ContainerFilterEnabled returns true when the scope has at least one container filter type enabled
func (fs *FilterScope) ContainerFilterEnabled() bool {
	return (fs.ContFilter.Enabled() && fs.ContFilter.Value()) ||
		(fs.NewContFilter.Enabled() && fs.NewContFilter.Value()) ||
		fs.ContIDFilter.Enabled()
}
