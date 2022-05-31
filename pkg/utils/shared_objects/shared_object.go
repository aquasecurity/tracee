package shared_objects

// SharedObjectIdentification is the unique identification of a SO in the system
type SharedObjectIdentification struct {
	Inode  uint64
	Device uint32
	Ctime  uint64
}

// SoExaminationInfo is the information of an SO needed to examine it
type SoExaminationInfo struct {
	Id      SharedObjectIdentification
	Path    string
	MountNS int
}

type ISOExportSymbolsLoader interface {
	GetSOExSymbols(info SoExaminationInfo) (map[string]bool, error)
}
