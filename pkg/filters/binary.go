package filters

import (
	"encoding/binary"
	"strconv"
	"strings"
	"unsafe"

	"kernel.org/pub/linux/libs/security/libcap/cap"

	bpf "github.com/aquasecurity/libbpfgo"

	"github.com/aquasecurity/tracee/pkg/capabilities"
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/utils"
	"github.com/aquasecurity/tracee/pkg/utils/proc"
)

type nsBinary struct {
	mntNS uint32
	path  string
}

type procInfo struct {
	newProc        bool
	followPolicies uint64
	mntNS          uint32
	binaryBytes    [maxBpfBinPathSize]byte
	binNoMnt       uint32
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
		return errfmt.WrapError(err)
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
			return errfmt.WrapError(err)
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
	procInfoMap   string
}

const (
	maxBpfBinPathSize = 256 // maximum binary path size supported by BPF (MAX_BIN_PATH_SIZE)
	bpfBinFilterSize  = 264 // the key size of the BPF binary filter map entry
)

func NewBPFBinaryFilter(binaryMapName, procInfoMap string) *BPFBinaryFilter {
	return &BPFBinaryFilter{
		BinaryFilter:  *NewBinaryFilter(),
		binaryMapName: binaryMapName,
		procInfoMap:   procInfoMap,
	}
}

func (f *BPFBinaryFilter) UpdateBPF(bpfModule *bpf.Module, policyID uint) error {
	if !f.Enabled() {
		return nil
	}

	err := f.populateBinaryMap(bpfModule, policyID)
	if err != nil {
		return errfmt.WrapError(err)
	}

	err = f.populateProcInfoMap(bpfModule)

	return errfmt.WrapError(err)
}

func (f *BPFBinaryFilter) populateBinaryMap(bpfModule *bpf.Module, policyID uint) error {

	binMap, err := bpfModule.GetMap(f.binaryMapName)
	if err != nil {
		return errfmt.WrapError(err)
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

		var equalInPolicies, equalitySetInPolicies uint64
		curVal, err := binMap.GetValue(unsafe.Pointer(&binBytes[0]))
		if err == nil {
			equalInPolicies = binary.LittleEndian.Uint64(curVal[0:8])
			equalitySetInPolicies = binary.LittleEndian.Uint64(curVal[8:16])
		}

		filterVal := make([]byte, 16)

		if eqVal == filterNotEqual {
			utils.ClearBit(&equalInPolicies, policyID)
		} else {
			utils.SetBit(&equalInPolicies, policyID)
		}
		utils.SetBit(&equalitySetInPolicies, policyID)
		binary.LittleEndian.PutUint64(filterVal[0:8], equalInPolicies)
		binary.LittleEndian.PutUint64(filterVal[8:16], equalitySetInPolicies)

		return binMap.Update(unsafe.Pointer(&binBytes[0]), unsafe.Pointer(&filterVal[0]))
	}

	// first initialize notEqual values since equality should take precedence
	for bin := range f.notEqual {
		if err = fn(bin, uint32(filterNotEqual)); err != nil {
			return errfmt.WrapError(err)
		}
	}

	// now - setup equality filters
	for bin := range f.equal {
		if err = fn(bin, uint32(filterEqual)); err != nil {
			return errfmt.WrapError(err)
		}
	}

	return nil
}

func (f *BPFBinaryFilter) populateProcInfoMap(bpfModule *bpf.Module) error {
	procInfoMap, err := bpfModule.GetMap(f.procInfoMap)
	if err != nil {
		return errfmt.WrapError(err)
	}

	binsToTrack := []nsBinary{}
	for bin := range f.equal {
		binsToTrack = append(binsToTrack, bin)
	}
	for bin := range f.notEqual {
		binsToTrack = append(binsToTrack, bin)
	}

	binsProcs, err := proc.GetAllBinaryProcs()
	if err != nil {
		return errfmt.WrapError(err)
	}

	for _, bin := range binsToTrack {
		procs := binsProcs[bin.path]
		for _, proc := range procs {
			binBytes := make([]byte, maxBpfBinPathSize)
			copy(binBytes, bin.path)
			binBytesCopy := (*[maxBpfBinPathSize]byte)(binBytes)
			procInfo := procInfo{
				newProc:        false,
				followPolicies: 0,
				mntNS:          bin.mntNS,
				binaryBytes:    *binBytesCopy,
				binNoMnt:       0, // always 0, see bin_no_mnt in tracee.bpf.c
			}
			err := procInfoMap.Update(unsafe.Pointer(&proc), unsafe.Pointer(&procInfo))
			if err != nil {
				return errfmt.WrapError(err)
			}
		}
	}

	return nil
}
