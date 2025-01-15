package filters

import (
	"math"
	"strconv"
	"strings"

	"golang.org/x/exp/maps"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/utils"
	"github.com/aquasecurity/tracee/pkg/utils/proc"
)

type NSBinary struct {
	MntNS uint32
	Path  string
}

type BinaryFilter struct {
	equal    map[NSBinary]struct{}
	notEqual map[NSBinary]struct{}
	enabled  bool
}

// Compile-time check to ensure that BinaryFilter implements the Cloner interface
var _ utils.Cloner[*BinaryFilter] = &BinaryFilter{}

func getHostMntNS() (uint32, error) {
	var ns int
	var err error

	ns, err = proc.GetProcNS(1, "mnt")
	if err != nil {
		return 0, errfmt.WrapError(err)
	}
	if ns < 0 || ns > math.MaxUint32 {
		return 0, errfmt.Errorf("invalid mnt namespace %d", ns)
	}

	return uint32(ns), nil
}

func NewBinaryFilter() *BinaryFilter {
	return &BinaryFilter{
		equal:    map[NSBinary]struct{}{},
		notEqual: map[NSBinary]struct{}{},
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
		var bin NSBinary
		if len(mntAndPath) == 1 {
			bin.Path = val
		} else if len(mntAndPath) == 2 {
			bin.Path = mntAndPath[1]
			if mntAndPath[0] == "host" {
				if hostMntNS == 0 {
					hostMntNS, err = getHostMntNS()
					if err != nil {
						return FailedToRetreiveHostNS()
					}
				}
				bin.MntNS = hostMntNS
			} else {
				mntNS, err := strconv.Atoi(mntAndPath[0])
				if err != nil {
					return InvalidValue(val)
				}
				if mntNS < 0 || mntNS > math.MaxUint32 {
					return InvalidValue(val)
				}
				bin.MntNS = uint32(mntNS)
			}
		} else {
			return InvalidValue(val)
		}

		if !strings.HasPrefix(bin.Path, "/") {
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

func (f *BinaryFilter) add(bin NSBinary, operator Operator) error {
	switch operator {
	case Equal:
		f.equal[bin] = struct{}{}
		return nil
	case NotEqual:
		f.notEqual[bin] = struct{}{}
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

func (f *BinaryFilter) MatchIfKeyMissing() bool {
	if len(f.equal) > 0 && len(f.notEqual) == 0 {
		return false
	}
	return true
}

type BinaryFilterEqualities struct {
	Equal    map[NSBinary]struct{}
	NotEqual map[NSBinary]struct{}
}

func (f *BinaryFilter) Equalities() BinaryFilterEqualities {
	if !f.Enabled() {
		return BinaryFilterEqualities{
			Equal:    map[NSBinary]struct{}{},
			NotEqual: map[NSBinary]struct{}{},
		}
	}

	return BinaryFilterEqualities{
		Equal:    maps.Clone(f.equal),
		NotEqual: maps.Clone(f.notEqual),
	}
}

func (f *BinaryFilter) Clone() *BinaryFilter {
	if f == nil {
		return nil
	}

	n := NewBinaryFilter()

	maps.Copy(n.equal, f.equal)
	maps.Copy(n.notEqual, f.notEqual)
	n.enabled = f.enabled

	return n
}
