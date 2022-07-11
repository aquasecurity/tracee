package sharedobjs

// ObjID is the unique identification of a SO in the system
type ObjID struct {
	Inode  uint64
	Device uint32
	Ctime  uint64
}

// ObjInfo is the information of an SO needed to examine it
type ObjInfo struct {
	Id      ObjID
	Path    string
	MountNS int
}

type DynamicSymbolsLoader interface {
	GetDynamicSymbols(info ObjInfo) (map[string]bool, error)
	GetExportedSymbols(info ObjInfo) (map[string]bool, error)
	GetImportedSymbols(info ObjInfo) (map[string]bool, error)
}

type dynamicSymbols struct {
	Exported map[string]bool
	Imported map[string]bool
}

func NewSOSymbols() dynamicSymbols {
	return dynamicSymbols{
		Exported: make(map[string]bool),
		Imported: make(map[string]bool),
	}
}
