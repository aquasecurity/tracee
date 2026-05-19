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
	MountNS uint32
}

type DynamicSymbolsLoader interface {
	GetDynamicSymbols(info ObjInfo) (map[string]bool, error)
	GetExportedSymbols(info ObjInfo) (map[string]bool, error)
	GetImportedSymbols(info ObjInfo) (map[string]bool, error)
	GetLocalSymbols(info ObjInfo) (map[string]bool, error)
}

// SymbolCategory is a bitmask describing how a symbol participates in a
// shared object: it may be Local, Imported, Exported, or any combination.
//
// Using a bitmask keeps a single map entry per symbol name even when the same
// name belongs to multiple categories (e.g. an Exported symbol is also Local).
// Storing one entry instead of three independent map entries is the primary
// memory win behind the redesign tracked by issue #4761.
type SymbolCategory uint8

const (
	CategoryLocal SymbolCategory = 1 << iota
	CategoryImported
	CategoryExported

	// CategoryDynamic is a convenience mask matching anything that appears in
	// the dynamic symbol table: imports plus exports.
	CategoryDynamic = CategoryImported | CategoryExported
)

// Symbols holds the classified symbols of a single shared object.
//
// Internally each unique symbol name maps to a SymbolCategory bitmask. Views
// onto a specific category (Local / Imported / Exported / Dynamic) are
// materialized on demand via View and are owned by the caller.
type Symbols struct {
	m map[string]SymbolCategory
}

// NewSOSymbols returns an empty Symbols container.
func NewSOSymbols() Symbols {
	return Symbols{m: make(map[string]SymbolCategory)}
}

// newSymbolsWithCapacity returns an empty Symbols container with the map
// pre-sized to at least capacity entries. Used by the parser to avoid map
// growth churn on large ELF symbol tables.
func newSymbolsWithCapacity(capacity int) *Symbols {
	return &Symbols{m: make(map[string]SymbolCategory, capacity)}
}

// add records name as belonging to cat. If name already exists, the new bits
// are OR'd into the existing categories.
func (s *Symbols) add(name string, cat SymbolCategory) {
	s.m[name] |= cat
}

// Has reports whether name matches any of the bits in mask.
func (s *Symbols) Has(name string, mask SymbolCategory) bool {
	return s.m[name]&mask != 0
}

// Len returns the number of distinct symbol names stored across all
// categories.
func (s *Symbols) Len() int { return len(s.m) }

// View returns a fresh map[string]bool of all names matching any of the bits
// in mask. The returned map is owned by the caller and is safe to mutate; it
// is recomputed on every call.
//
// View intentionally allocates: the live-heap footprint of cached Symbols is
// constant in the number of unique names, regardless of how many categories
// each name belongs to. Callers that need repeated category iteration over
// the same object should cache the result themselves.
func (s *Symbols) View(mask SymbolCategory) map[string]bool {
	if len(s.m) == 0 {
		return map[string]bool{}
	}
	out := make(map[string]bool, len(s.m))
	for name, c := range s.m {
		if c&mask != 0 {
			out[name] = true
		}
	}
	return out
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
