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
	GetDynamicSymbols(info ObjInfo) (map[string]struct{}, error)
	GetExportedSymbols(info ObjInfo) (map[string]struct{}, error)
	GetImportedSymbols(info ObjInfo) (map[string]struct{}, error)
}

type DynamicSymbols struct {
	Exported map[string]struct{}
	Imported map[string]struct{}
}

func NewSOSymbols() DynamicSymbols {
	return DynamicSymbols{
		Exported: make(map[string]struct{}),
		Imported: make(map[string]struct{}),
	}
}

type UnsupportedFileError struct {
	err error
}

func InitUnsupportedFileError(err error) *UnsupportedFileError {
	return &UnsupportedFileError{err: err}
}

func (fileTypeErr *UnsupportedFileError) Error() string {
	return fileTypeErr.err.Error()
}

func (fileTypeErr *UnsupportedFileError) Unwrap() error {
	return fileTypeErr.err
}
