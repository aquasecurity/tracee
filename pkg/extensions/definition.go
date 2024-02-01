package extensions

import (
	"fmt"
	"sort"
	"sync"
	"unsafe"

	"github.com/Masterminds/semver/v3"
	"kernel.org/pub/linux/libs/security/libcap/cap"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/types/trace"
)

const (
	// use (0xfffffff - x) as most overflows behavior is undefined
	All            int = 0xfffffff - 1
	Undefined      int = 0xfffffff - 2
	Sys32Undefined int = 0xfffffff - 3
	Unsupported    int = 10000
)

// Make it sortable by ID

type ByID []Definition

func (a ByID) Len() int           { return len(a) }
func (a ByID) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByID) Less(i, j int) bool { return a[i].id < a[j].id }

//
// DefinitionsPerExtension (IDs are unique across extensions and synced with eBPF)
//

type DefinitionsPerExtension struct {
	definitions map[string]map[int]Definition // map[extension]map[id]Definition
	mutex       *sync.RWMutex
}

// GetExtensions returns all extensions names that have definitions.
func (d *DefinitionsPerExtension) GetExtensions() []string {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	keys := make([]string, 0, len(d.definitions))

	for k := range d.definitions {
		keys = append(keys, k)
	}

	return keys
}

// GetAll returns all definitions for the given extension.
func (d *DefinitionsPerExtension) GetAll(ext string) []Definition {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	definitions := make([]Definition, 0, len(d.definitions[ext]))

	for _, def := range d.definitions[ext] {
		definitions = append(definitions, def)
	}
	sort.Sort(ByID(definitions))

	return definitions
}

// GetAllFromAllExts returns all definitions from all extensions.
func (d *DefinitionsPerExtension) GetAllFromAllExts() []Definition {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	definitions := make([]Definition, 0, len(d.definitions))

	for _, ext := range d.definitions {
		for _, def := range ext {
			definitions = append(definitions, def)
		}
	}
	sort.Sort(ByID(definitions))

	return definitions
}

// GetIDs returns the event IDs for the given extension and definition name.
func (d *DefinitionsPerExtension) GetIDByName(ext, name string) (int, bool) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()
	return d.getIDByNameFromAny(ext, name)
}

// GetIDsFromAny returns the event IDs for the given definition name from any extension.
func (d *DefinitionsPerExtension) GetIDByNameFromAny(name string) (int, bool) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	for ext := range d.definitions {
		if id, ok := d.getIDByNameFromAny(ext, name); ok {
			return id, true
		}
	}

	return Undefined, false
}

func (d *DefinitionsPerExtension) getIDByNameFromAny(ext, name string) (int, bool) {
	for id, def := range d.definitions[ext] {
		if def.GetName() == name {
			return id, true
		}
	}
	return Undefined, false
}

// GetByID returns the definition for the given extension and event ID.
func (d *DefinitionsPerExtension) GetByID(ext string, id int) Definition {
	d.mutex.RLock()
	defer d.mutex.RUnlock()
	return d.getByID(ext, id)
}

// GetByIDOk returns the definition for the given extension and event ID.
func (d *DefinitionsPerExtension) GetByIDOk(ext string, id int) (Definition, bool) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()
	return d.getByIDOk(ext, id)
}

func (d *DefinitionsPerExtension) getByID(ext string, id int) Definition {
	def, ok := d.definitions[ext][id]
	if !ok {
		logger.Debugw("definition id not found", "id", id)
		return Definition{id: Undefined}
	}
	return def
}

func (d *DefinitionsPerExtension) getByIDOk(ext string, id int) (Definition, bool) {
	def, ok := d.definitions[ext][id]
	if !ok {
		return Definition{id: Undefined}, false
	}
	return def, true
}

// GetByIDFromAny returns the definition for the given event ID from any extension.
func (d *DefinitionsPerExtension) GetByIDFromAny(id int) Definition {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	for ext := range d.definitions {
		if def, ok := d.getByIDOk(ext, id); ok {
			return def
		}
	}

	return Definition{id: Undefined}
}

// IsDefined returns true if the given extension has the given event ID.
func (d *DefinitionsPerExtension) IsDefined(ext string, id int) bool {
	d.mutex.RLock()
	defer d.mutex.RUnlock()
	_, ok := d.definitions[ext][id]
	return ok
}

// IsDefinedInAny returns true if any extension has the given event ID.
func (d *DefinitionsPerExtension) IsDefinedInAny(id int) bool {
	d.mutex.RLock()
	defer d.mutex.RUnlock()
	for _, ext := range d.definitions {
		if _, ok := ext[id]; ok {
			return true
		}
	}
	return false
}

// Length returns the number of definitions for the given extension.
func (d *DefinitionsPerExtension) Length(ext string) int {
	d.mutex.RLock()
	defer d.mutex.RUnlock()
	return len(d.definitions[ext])
}

// LengthAllExts returns the number of definitions from all extensions.
func (d *DefinitionsPerExtension) LengthAllExts() int {
	d.mutex.RLock()
	defer d.mutex.RUnlock()
	total := 0
	for _, ext := range d.definitions {
		total += len(ext)
	}
	return total
}

// Add adds the given definition to the given extension.
func (d *DefinitionsPerExtension) Add(ext string, id int, def Definition) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	return d.add(ext, id, def)
}

// AddBatch adds the given definitions to the given extension.
func (d *DefinitionsPerExtension) AddBatch(ext string, given map[int]Definition) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	for id, def := range given {
		err := d.add(ext, id, def)
		if err != nil {
			return err
		}
	}

	return nil
}

func (d *DefinitionsPerExtension) add(ext string, givenId int, givenDef Definition) error {
	if _, ok := d.definitions[ext]; !ok {
		d.definitions[ext] = map[int]Definition{}
	}
	if _, ok := d.definitions[ext][givenId]; ok {
		return errfmt.Errorf("definition id already exists: %v", givenId)
	}
	n := givenDef.GetName()
	if _, ok := d.getIDByNameFromAny(ext, n); ok {
		return errfmt.Errorf("definition name already exists: %v", n)
	}

	d.definitions[ext][givenId] = givenDef

	return nil
}

// NamesToIDs returns a map of event names to event IDs for the given extension.
func (d *DefinitionsPerExtension) NamesToIDs(ext string) map[string]int {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	namesToIds := make(map[string]int, len(d.definitions[ext]))

	for id, def := range d.definitions[ext] {
		namesToIds[def.GetName()] = id
	}

	return namesToIds
}

// NamesToIDsFromAllExts returns a map of event names to event IDs from all extensions.
func (d *DefinitionsPerExtension) NamesToIDsFromAllExts() map[string]int {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	namesToIds := make(map[string]int)

	for ext := range d.definitions {
		for id, def := range d.definitions[ext] {
			namesToIds[def.GetName()] = id
		}
	}

	return namesToIds
}

// IDs32ToIDs returns a map of 32-bit event IDs to event IDs for the given extension.
func (d *DefinitionsPerExtension) IDs32ToIDs(ext string) map[int]int {
	d.mutex.RLock()
	defer d.mutex.RUnlock()
	idS32ToIDs := make(map[int]int, len(d.definitions[ext]))

	for id, def := range d.definitions[ext] {
		id32 := def.GetID32Bit()
		if id32 != Sys32Undefined {
			idS32ToIDs[id32] = id
		}
	}

	return idS32ToIDs
}

// IDs32ToIDsFromAllExts returns a map of 32-bit event IDs to event IDs from all extensions.
func (d *DefinitionsPerExtension) IDs32ToIDsFromAllExts() map[int]int {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	idS32ToIDs := make(map[int]int)

	for ext := range d.definitions {
		for id, def := range d.definitions[ext] {
			id32 := def.GetID32Bit()
			if id32 != Sys32Undefined {
				idS32ToIDs[id32] = id
			}
		}
	}

	return idS32ToIDs
}

// GetTailCalls returns the tailcalls for the given extension.
func (d *DefinitionsPerExtension) GetTailCalls(ext string) []TailCall {
	d.mutex.RLock()
	defer d.mutex.RUnlock()
	return d.getTailCalls(ext)
}

// GetTailCallsFromAllExts returns the tailcalls from all extensions.
func (d *DefinitionsPerExtension) GetTailCallsFromAllExts() []TailCall {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	calls := make([]TailCall, 0, len(d.definitions))

	for ext := range d.definitions {
		calls = append(calls, d.getTailCalls(ext)...)
	}

	return calls
}

func (d *DefinitionsPerExtension) getTailCalls(ext string) []TailCall {
	calls := make([]TailCall, 0, len(d.definitions[ext]))

	for id, def := range d.definitions[ext] {
		state, ok := States.GetOk(ext, id)
		if !ok {
			continue
		}
		// Only events bring traced will provide their tailcalls.
		if state.AnySubmitEnabled() {
			calls = append(calls, def.GetDependencies().GetTailCalls()...)
		}
	}

	return calls
}

//
// Definition
//

type Definition struct {
	id           int
	id32Bit      int
	name         string
	version      Version
	description  string
	docPath      string // Relative to the 'doc/events' directory
	internal     bool
	syscall      bool
	dependencies Dependencies
	sets         []string
	params       []trace.ArgMeta
	properties   map[string]interface{}
}

func NewDefinition(
	id int,
	id32Bit int,
	name string,
	version Version,
	description string,
	docPath string,
	internal bool,
	syscall bool,
	sets []string,
	deps Dependencies,
	params []trace.ArgMeta,
	properties map[string]interface{},
) Definition {
	return Definition{
		id:           id,
		id32Bit:      id32Bit,
		name:         name,
		version:      version,
		description:  description,
		docPath:      docPath,
		internal:     internal,
		syscall:      syscall,
		dependencies: deps,
		sets:         sets,
		params:       params,
		properties:   properties,
	}
}

// Getters (immutable data)

func (d Definition) GetID() int {
	return d.id
}

func (d Definition) GetID32Bit() int {
	return d.id32Bit
}

func (d Definition) GetName() string {
	return d.name
}

func (d Definition) GetVersion() Version {
	return d.version
}

func (d Definition) GetDescription() string {
	return d.description
}

func (d Definition) GetDocPath() string {
	return d.docPath
}

func (d Definition) IsInternal() bool {
	return d.internal
}

func (d Definition) IsSyscall() bool {
	return d.syscall
}

func (d Definition) GetDependencies() Dependencies {
	return d.dependencies
}

func (d Definition) GetSets() []string {
	return d.sets
}

func (d Definition) GetParams() []trace.ArgMeta {
	return d.params
}

func (d Definition) IsSignature() bool {
	if d.id >= StartSignatureID && d.id <= MaxSignatureID {
		return true
	}

	return false
}

func (d Definition) IsNetwork() bool {
	if d.id >= NetPacketIPv4 && d.id <= MaxUserNetID {
		return true
	}

	return false
}

func (d Definition) GetProperties() map[string]interface{} {
	return d.properties
}

//
// Dependencies
//

type Dependencies struct {
	ids          []int
	kSymbols     []KSymDep
	probes       []ProbeDep
	tailCalls    []TailCall
	capabilities CapsDep
}

func NewDependencies(
	givenIDs []int,
	givenkSymbols []KSymDep,
	givenProbes []ProbeDep,
	givenTailCalls []TailCall,
	givenCapabilities CapsDep,
) Dependencies {
	return Dependencies{
		ids:          givenIDs,
		kSymbols:     givenkSymbols,
		probes:       givenProbes,
		tailCalls:    givenTailCalls,
		capabilities: givenCapabilities,
	}
}

func (d Dependencies) GetIDs() []int {
	if d.ids == nil {
		return []int{}
	}
	return d.ids
}

func (d Dependencies) GetKSymbols() []KSymDep {
	if d.kSymbols == nil {
		return []KSymDep{}
	}
	return d.kSymbols
}

func (d Dependencies) GetRequiredKSymbols() []KSymDep {
	var requiredKSymbols []KSymDep
	for _, kSymbol := range d.kSymbols {
		if kSymbol.required {
			requiredKSymbols = append(requiredKSymbols, kSymbol)
		}
	}
	return requiredKSymbols
}

func (d Dependencies) GetProbes() []ProbeDep {
	if d.probes == nil {
		return []ProbeDep{}
	}
	return d.probes
}

func (d Dependencies) GetTailCalls() []TailCall {
	if d.tailCalls == nil {
		return []TailCall{}
	}
	return d.tailCalls
}

func (d Dependencies) GetCapabilities() CapsDep {
	return d.capabilities
}

// ProbeDep

type ProbeDep struct {
	handle   int
	required bool // tracee fails if probe can't be attached
}

func (p ProbeDep) GetHandle() int {
	return p.handle
}

func (p ProbeDep) IsRequired() bool {
	return p.required
}

// KSymbol

type KSymDep struct {
	symbol   string
	required bool // tracee fails if symbol is not found
}

func (ks KSymDep) GetSymbolName() string {
	return ks.symbol
}

func (ks KSymDep) IsRequired() bool {
	return ks.required
}

// Capabilities

type CapsDep struct {
	base []cap.Value // always effective
	ebpf []cap.Value // effective when using eBPF
}

func (c CapsDep) GetBase() []cap.Value {
	if c.base == nil {
		return []cap.Value{}
	}
	return c.base
}

func (c CapsDep) GetEBPF() []cap.Value {
	if c.ebpf == nil {
		return []cap.Value{}
	}
	return c.ebpf
}

// TailCall

const (
	TailVfsWrite  uint32 = iota // Index of a function to be used in a bpf tailcall.
	TailVfsWritev               // Matches defined values in ebpf code for prog_array map.
	TailSendBin
	TailSendBinTP
	TailKernelWrite
	TailSchedProcessExecEventSubmit
	TailVfsRead
	TailVfsReadv
	TailExecBinprm1
	TailExecBinprm2
	TailHiddenKernelModuleProc
	TailHiddenKernelModuleKset
	TailHiddenKernelModuleModTree
	TailHiddenKernelModuleNewModOnly
	MaxTail
)

type TailCall struct {
	mapName  string
	progName string
	indexes  []uint32
}

func (tc TailCall) GetIndexes() []uint32 {
	if tc.indexes == nil {
		return []uint32{}
	}
	return tc.indexes
}

func (tc TailCall) GetMapName() string {
	return tc.mapName
}

func (tc TailCall) GetProgName() string {
	return tc.progName
}

func (tc TailCall) Init() error {
	tailCallMapName := tc.GetMapName()
	tailCallProgName := tc.GetProgName()
	tailCallIndexes := tc.GetIndexes()

	// Pick eBPF map by name.
	bpfMap, err := Modules.Get("core").GetMap(tailCallMapName)
	if err != nil {
		return errfmt.WrapError(err)
	}
	// Pick eBPF program by name.
	bpfProg, err := Modules.Get("core").GetProgram(tailCallProgName)
	if err != nil {
		return errfmt.Errorf("could not get BPF program %s: %v", tailCallProgName, err)
	}
	// Pick eBPF program file descriptor.
	bpfProgFD := bpfProg.FileDescriptor()
	if bpfProgFD < 0 {
		return errfmt.Errorf("could not get BPF program FD for %s: %v", tailCallProgName, err)
	}

	// Pick all indexes (event, or syscall, IDs) the BPF program should be related to.
	for _, index := range tailCallIndexes {
		// Workaround: Do not map eBPF program to unsupported syscalls (arm64, e.g.)
		if index >= uint32(Unsupported) {
			continue
		}
		// Update given eBPF map with the eBPF program file descriptor at given index.
		err := bpfMap.Update(unsafe.Pointer(&index), unsafe.Pointer(&bpfProgFD))
		if err != nil {
			return errfmt.WrapError(err)
		}
	}

	return nil
}

//
// Version
//

// 1. Major field is bumped whenever some data the event used to have was changed
//    (example: a field was renamed or removed)
// 2. Minor field is bumped whenever a non breaking change occurs (example: a new field
//    was added to the event).
// 3. Patch field is bumped whenever something is changed in the way the event works
//    internally (example: some bug was fixed in the code).

type Version struct {
	major uint64
	minor uint64
	patch uint64
}

func NewVersion(major, minor, patch uint64) Version {
	return Version{
		major,
		minor,
		patch,
	}
}

func NewVersionFromString(v string) (Version, error) {
	version, err := semver.StrictNewVersion(v)
	if err != nil {
		return Version{}, err
	}

	return Version{
		major: version.Major(),
		minor: version.Minor(),
		patch: version.Patch(),
	}, nil
}

func (v Version) Major() uint64 {
	return v.major
}

func (v Version) Minor() uint64 {
	return v.minor
}

func (v Version) Patch() uint64 {
	return v.patch
}

func (v Version) String() string {
	return fmt.Sprintf("%d.%d.%d", v.major, v.minor, v.patch)
}
