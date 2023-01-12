package filters

import (
	"encoding/binary"
	"strconv"
	"strings"
	"unsafe"

	"github.com/aquasecurity/tracee/pkg/capabilities"
	"github.com/aquasecurity/tracee/pkg/utils"
	"github.com/aquasecurity/tracee/pkg/utils/proc"

	bpf "github.com/aquasecurity/libbpfgo"

	"kernel.org/pub/linux/libs/security/libcap/cap"
)

type nsBinary struct {
	mntNS uint32
	path  string
}

type BinaryFilter struct {
	equal    map[nsBinary]bool
	notEqual map[nsBinary]bool
	enabled  bool
}

func getHostMntNS() (uint32, error) {
	var ns int
	var err error

	err = capabilities.GetInstance().Requested(func() error {
		ns, err = proc.GetProcNS(1, "mnt")
		return err
	},
		cap.DAC_READ_SEARCH,
		cap.SYS_PTRACE,
	)
	if err != nil {
		return 0, err
	}

	return uint32(ns), nil
}

func NewBinaryFilter() *BinaryFilter {
	return &BinaryFilter{
		equal:    map[nsBinary]bool{},
		notEqual: map[nsBinary]bool{},
	}
}

func (f *BinaryFilter) Parse(operatorAndValues string) error {
	if len(operatorAndValues) < 2 {
		return InvalidExpression(operatorAndValues)
	}
	valuesString := string(operatorAndValues[1:])
	operatorString := string(operatorAndValues[0])

	if operatorString == "!" {
		if len(operatorAndValues) < 3 {
			return InvalidExpression(operatorAndValues)
		}
		operatorString = operatorAndValues[0:2]
		valuesString = operatorAndValues[2:]
	}

	values := strings.Split(valuesString, ",")

	var hostMntNS uint32
	var err error

	for _, val := range values {
		mntAndPath := strings.Split(val, ":")
		var bin nsBinary
		if len(mntAndPath) == 1 {
			bin.path = val
		} else if len(mntAndPath) == 2 {
			bin.path = mntAndPath[1]
			if mntAndPath[0] == "host" {
				if hostMntNS == 0 {
					hostMntNS, err = getHostMntNS()
					if err != nil {
						return FailedToRetreiveHostNS()
					}
				}
				bin.mntNS = hostMntNS
			} else {
				mntNS, err := strconv.Atoi(mntAndPath[0])
				if err != nil {
					return InvalidValue(val)
				}
				bin.mntNS = uint32(mntNS)
			}
		} else {
			return InvalidValue(val)
		}

		if !strings.HasPrefix(bin.path, "/") {
			return InvalidValue(val)
		}

		err := f.add(bin, stringToOperator(operatorString))
		if err != nil {
			return err
		}
	}

	f.Enable()

	return nil
}

func (f *BinaryFilter) add(bin nsBinary, operator Operator) error {
	switch operator {
	case Equal:
		f.equal[bin] = true
		return nil
	case NotEqual:
		f.notEqual[bin] = true
		return nil
	default:
		return UnsupportedOperator(operator)
	}
}

func (f *BinaryFilter) Enable() {
	f.enabled = true
}

func (f *BinaryFilter) Disable() {
	f.enabled = false
}

func (f *BinaryFilter) Enabled() bool {
	return f.enabled
}

func (f *BinaryFilter) FilterOut() bool {
	if len(f.equal) > 0 && len(f.notEqual) == 0 {
		return false
	} else {
		return true
	}
}

type BPFBinaryFilter struct {
	BinaryFilter
	binaryMapName string
}

func NewBPFBinaryFilter(binaryMapName string) *BPFBinaryFilter {
	return &BPFBinaryFilter{
		BinaryFilter:  *NewBinaryFilter(),
		binaryMapName: binaryMapName,
	}
}

func (f *BPFBinaryFilter) UpdateBPF(bpfModule *bpf.Module, filterScopeID uint) error {
	const (
		maxBpfBinPathSize = 256 // maximum binary path size supported by BPF (MAX_BIN_PATH_SIZE)
		bpfBinFilterSize  = 264 // the key size of the BPF binary filter map entry
	)

	if !f.Enabled() {
		return nil
	}

	binMap, err := bpfModule.GetMap(f.binaryMapName)
	if err != nil {
		return err
	}

	fn := func(bin nsBinary, eqVal uint32) error {
		if len(bin.path) > maxBpfBinPathSize {
			return InvalidValue(bin.path)
		}
		binBytes := make([]byte, bpfBinFilterSize)
		if bin.mntNS == 0 {
			// If no mount namespace given, bpf map key is only the path
			copy(binBytes, bin.path)
		} else {
			// otherwise, key is composed of the mount namespace and the path
			binary.LittleEndian.PutUint32(binBytes, bin.mntNS)
			copy(binBytes[4:], bin.path)
		}

		var equalInScopes, equalitySetInScopes uint64
		curVal, err := binMap.GetValue(unsafe.Pointer(&binBytes[0]))
		if err == nil {
			equalInScopes = binary.LittleEndian.Uint64(curVal[0:8])
			equalitySetInScopes = binary.LittleEndian.Uint64(curVal[8:16])
		}

		filterVal := make([]byte, 16)

		if eqVal == filterNotEqual {
			utils.ClearBit(&equalInScopes, filterScopeID)
		} else {
			utils.SetBit(&equalInScopes, filterScopeID)
		}
		utils.SetBit(&equalitySetInScopes, filterScopeID)
		binary.LittleEndian.PutUint64(filterVal[0:8], equalInScopes)
		binary.LittleEndian.PutUint64(filterVal[8:16], equalitySetInScopes)

		return binMap.Update(unsafe.Pointer(&binBytes[0]), unsafe.Pointer(&filterVal[0]))
	}

	// first initialize notEqual values since equality should take precedence
	for bin := range f.notEqual {
		if err = fn(bin, uint32(filterNotEqual)); err != nil {
			return err
		}
	}

	// now - setup equality filters
	for bin := range f.equal {
		if err = fn(bin, uint32(filterEqual)); err != nil {
			return err
		}
	}

	return nil
}
