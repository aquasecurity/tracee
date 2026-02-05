// Package elf provides comprehensive ELF binary analysis utilities.
//
// This package offers functionality for analyzing ELF binaries including:
// - Symbol resolution and offset calculation
// - Function instruction analysis (finding RET instructions)
// - Support for multiple architectures (x86_64, ARM64)
// - Memory-optimized symbol loading with selective caching
// - Support for different symbol types (Rust, C++, etc.)
//
// The main type is ElfAnalyzer which provides a high-level interface
// for ELF binary analysis with efficient memory management through
// memory mapping and selective symbol loading.
package elf

import (
	"debug/elf"
	"errors"
	"io"
	"os"
	"runtime"
	"syscall"

	"golang.org/x/arch/arm64/arm64asm"
	"golang.org/x/arch/x86/x86asm"

	"github.com/aquasecurity/tracee/common/errfmt"
	"github.com/aquasecurity/tracee/common/fileutil"
	"github.com/aquasecurity/tracee/common/logger"
)

type ElfAnalyzer struct {
	filePath          string
	file              *os.File
	mmapData          []byte
	elf               *elf.File
	wantedSymbols     []WantedSymbol
	wantedSymbolsOnly bool

	// Cached data
	symbols        map[string]*ElfSymbol
	goVersion      *GoVersion
	goVersionError error
}

var ErrSymbolNotFound = errors.New("symbol not found")

// GetHostElfMachine returns the ELF machine type for the host architecture.
// Tracee only supports x86_64 and arm64.
func GetHostElfMachine() elf.Machine {
	switch runtime.GOARCH {
	case "amd64":
		return elf.EM_X86_64
	case "arm64":
		return elf.EM_AARCH64
	default:
		return elf.EM_NONE
	}
}

// GetCompatibleElfMachines returns all ELF machine types that can run on the host.
// On 64-bit hosts, this includes both native 64-bit and 32-bit compat binaries.
// For example, on x86_64 hosts, both EM_X86_64 and EM_386 (i386) binaries can run.
func GetCompatibleElfMachines() []elf.Machine {
	switch runtime.GOARCH {
	case "amd64":
		// x86_64 can run both 64-bit and 32-bit (i386) binaries
		return []elf.Machine{elf.EM_X86_64, elf.EM_386}
	case "arm64":
		// ARM64 can run both 64-bit and 32-bit ARM binaries
		return []elf.Machine{elf.EM_AARCH64, elf.EM_ARM}
	default:
		return []elf.Machine{}
	}
}

// IsMachineCompatibleWithHost checks if the given ELF machine type can run on this host.
func IsMachineCompatibleWithHost(machine elf.Machine) bool {
	compatibleMachines := GetCompatibleElfMachines()
	for _, m := range compatibleMachines {
		if m == machine {
			return true
		}
	}
	return false
}

// Is32BitMachine returns true if the given ELF machine type is a 32-bit architecture.
func Is32BitMachine(machine elf.Machine) bool {
	switch machine {
	case elf.EM_386, elf.EM_ARM:
		return true
	default:
		return false
	}
}

// HasElfMagic checks if the given bytes start with the ELF magic number (0x7F 'ELF').
// This is a fast check that only validates the first 4 bytes.
func HasElfMagic(bytesArray []byte) bool {
	if len(bytesArray) >= 4 {
		if bytesArray[0] == 127 && bytesArray[1] == 69 && bytesArray[2] == 76 && bytesArray[3] == 70 {
			return true
		}
	}
	return false
}

// IsElf checks if the given bytes represent a valid ELF file.
// Currently this only checks the magic number, but can be expanded in the future
// to include more comprehensive ELF validation.
func IsElf(bytesArray []byte) bool {
	return HasElfMagic(bytesArray)
}

// IsElfFile checks if the file at the given path is an ELF file (fast magic-only check).
func IsElfFile(filePath string) bool {
	file, err := os.Open(filePath)
	if err != nil {
		return false
	}
	defer func() {
		if err := file.Close(); err != nil {
			logger.Debugw("Closing ELF file", "path", filePath, "error", err)
		}
	}()

	magic := make([]byte, 4)
	n, err := file.Read(magic)
	if err != nil || n < 4 {
		return false
	}

	return HasElfMagic(magic)
}

func NewElfAnalyzer(filePath string, wantedSymbols []WantedSymbol) (*ElfAnalyzer, error) {
	var err error
	var data []byte
	var mmapFile io.ReaderAt
	var elfFile *elf.File
	var ea *ElfAnalyzer

	file, err := os.Open(filePath)
	if err != nil {
		return nil, errfmt.WrapError(err)
	}

	stat, err := file.Stat()
	if err != nil {
		goto exit_close
	}

	data, err = syscall.Mmap(int(file.Fd()), 0, int(stat.Size()), syscall.PROT_READ, syscall.MAP_PRIVATE)
	if err != nil {
		goto exit_close
	}

	mmapFile = fileutil.NewProtectedReader(data)

	elfFile, err = elf.NewFile(mmapFile)
	if err != nil {
		goto exit_munmap
	}

	ea = &ElfAnalyzer{
		filePath: filePath,
		file:     file,
		mmapData: data,
		elf:      elfFile,
	}

	if len(wantedSymbols) > 0 {
		ea.wantedSymbolsOnly = true
		ea.wantedSymbols = wantedSymbols
	}

	return ea, nil

exit_munmap:
	if errMunmap := syscall.Munmap(data); errMunmap != nil {
		logger.Errorw("Error unmapping file", "path", filePath, "error", errMunmap)
	}
exit_close:
	if errClose := file.Close(); errClose != nil {
		logger.Errorw("Error closing file", "path", filePath, "error", errClose)
	}
	return nil, errfmt.WrapError(err)
}

func (ea *ElfAnalyzer) Close() error {
	if err := syscall.Munmap(ea.mmapData); err != nil {
		return errfmt.WrapError(err)
	}

	// No need to call b.elf.Close() because b.elf was created using elf.NewFile() and not elf.Open()
	if err := ea.file.Close(); err != nil {
		return errfmt.WrapError(err)
	}

	return nil
}

func (ea *ElfAnalyzer) GetFilePath() string {
	return ea.filePath
}

// GetMachine returns the ELF machine type (architecture) of the binary.
func (ea *ElfAnalyzer) GetMachine() elf.Machine {
	return ea.elf.Machine
}

// Is32Bit returns true if the ELF binary is a 32-bit architecture.
func (ea *ElfAnalyzer) Is32Bit() bool {
	return Is32BitMachine(ea.elf.Machine)
}

// IsArchCompatible checks if the ELF binary's architecture is compatible with the host.
// On x86_64 hosts, both 64-bit (EM_X86_64) and 32-bit (EM_386) binaries are compatible.
func (ea *ElfAnalyzer) IsArchCompatible() bool {
	return IsMachineCompatibleWithHost(ea.GetMachine())
}

func (ea *ElfAnalyzer) GetFunctionRetInsts(funcName string) ([]uint64, error) {
	const maxFunctionSize = 100 * 1024 // 100KB

	symbol, err := ea.GetSymbol(funcName)
	if err != nil {
		return nil, err
	}

	// Validate section index bounds
	if int(symbol.Section) >= len(ea.elf.Sections) || symbol.Section < 0 {
		return nil, errfmt.Errorf("invalid section %d for symbol %s", symbol.Section, symbol.Name)
	}

	section := ea.elf.Sections[symbol.Section]
	if section.Flags != elf.SHF_ALLOC|elf.SHF_EXECINSTR {
		return nil, errfmt.Errorf("symbol %s not in executable section", symbol.Name)
	}

	// Read function bytes
	if symbol.Size > maxFunctionSize {
		return nil, errfmt.Errorf("function %s is too large (%d bytes)", symbol.Name, symbol.Size)
	}
	bytes := make([]byte, symbol.Size)
	n, err := section.ReadAt(bytes, int64(symbol.Value-section.Addr))
	if err != nil {
		return nil, errfmt.WrapError(err)
	}

	return findRetInsts(symbol.Value-section.Addr+section.Offset, bytes[:n], ea.elf.Machine)
}

func findRetInsts(funcOffset uint64, bytes []byte, machine elf.Machine) ([]uint64, error) {
	switch machine {
	case elf.EM_X86_64:
		return findRetInstsX86_64(funcOffset, bytes)
	case elf.EM_AARCH64:
		return findRetInstsARM64(funcOffset, bytes)
	default:
		return nil, errfmt.Errorf("unsupported architecture %s", machine.String())
	}
}

func findRetInstsX86_64(funcOffset uint64, bytes []byte) ([]uint64, error) {
	offsets := make([]uint64, 0)

	for i := 0; i < len(bytes); {
		inst, err := x86asm.Decode(bytes[i:], 64)
		if err != nil {
			return nil, err
		}
		if inst.Op == x86asm.RET {
			offsets = append(offsets, uint64(i)+funcOffset)
		}
		i += inst.Len
	}

	if len(offsets) == 0 {
		return nil, errors.New("could not find any RET instructions")
	}

	return offsets, nil
}

func findRetInstsARM64(funcOffset uint64, bytes []byte) ([]uint64, error) {
	const arm64InstSize = 4

	offsets := make([]uint64, 0)

	for i := 0; i < len(bytes); {
		// Ignore errors because ARM64 instructions are a fixed
		// size and we can just skip to the next instruction
		inst, _ := arm64asm.Decode(bytes[i:])
		if inst.Op == arm64asm.RET {
			offsets = append(offsets, uint64(i)+funcOffset)
		}
		i += arm64InstSize
	}

	if len(offsets) == 0 {
		return nil, errors.New("could not find any RET instructions")
	}

	return offsets, nil
}
