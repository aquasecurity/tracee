package events

type Definition struct {
	id           ID // TODO: use id ?
	id32Bit      ID
	name         string
	version      Version
	description  string
	internal     bool
	syscall      bool
	dependencies DependencyStrategy
	sets         []string
	fields       []DataField
	properties   map[string]interface{}
}

func NewDefinition(
	id ID,
	id32Bit ID,
	name string,
	version Version,
	description string,
	internal bool,
	syscall bool,
	sets []string,
	deps DependencyStrategy,
	fields []DataField,
	properties map[string]interface{},
) Definition {
	return Definition{
		id:           id,
		id32Bit:      id32Bit,
		name:         name,
		version:      version,
		description:  description,
		internal:     internal,
		syscall:      syscall,
		dependencies: deps,
		sets:         sets,
		fields:       fields,
		properties:   properties,
	}
}

// Getters (immutable data)

func (d Definition) GetID() ID {
	return d.id
}

func (d Definition) GetID32Bit() ID {
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

func (d Definition) IsInternal() bool {
	return d.internal
}

func (d Definition) IsSyscall() bool {
	return d.syscall
}

func (d Definition) GetDependencies() DependencyStrategy {
	return d.dependencies
}

func (d Definition) GetSets() []string {
	return d.sets
}

func (d Definition) GetFields() []DataField {
	return d.fields
}

func (d Definition) IsSignature() bool {
	if d.id >= StartSignatureID && d.id <= MaxSignatureID {
		return true
	}

	return false
}

func (d Definition) IsDetector() bool {
	// Check if event is in the predefined detector ID range
	if d.id >= StartPredefinedDetectorID && d.id <= MaxPredefinedDetectorID {
		return true
	}

	// Check if event is in the dynamic detector ID range
	if d.id >= StartDetectorID && d.id <= MaxDetectorID {
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

func (d Definition) NotValid() bool {
	return d.id == Undefined || d.id == Unsupported
}
