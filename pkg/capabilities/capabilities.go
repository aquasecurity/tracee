package capabilities

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"kernel.org/pub/linux/libs/security/libcap/cap"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/logger"
)

var caps *Capabilities // singleton for all packages

var once sync.Once

type RingType int

const (
	Full     RingType = iota // All capabilties are effective
	EBPF                     // eBPF needed capabilities are effective
	Specific                 // Specific requested capabilities are effective
	Base                     // Capabilities that are always effective
)

type Capabilities struct {
	have   *cap.Set
	all    map[cap.Value]map[RingType]bool
	bypass bool
	lock   *sync.Mutex // big lock to guarantee all threads are on the same ring
}

// Initialize initializes the "caps" instance (singleton).
func Initialize(bypass bool) error {
	var err error

	once.Do(func() {
		caps = &Capabilities{}
		err = caps.initialize(bypass)
	})

	return errfmt.WrapError(err)
}

// GetInstance returns current "caps" instance. It initializes capabilities if
// needed, bypassing the privilege dropping by default.
func GetInstance() *Capabilities {
	if caps == nil {
		err := Initialize(true)
		if err != nil {
			return nil
		}
	}

	return caps
}

func (c *Capabilities) initialize(bypass bool) error {
	if bypass {
		c.bypass = true
		return nil
	}

	c.lock = new(sync.Mutex)
	c.all = make(map[cap.Value]map[RingType]bool)

	for v := cap.Value(0); v < cap.MaxBits(); v++ {
		c.all[v] = make(map[RingType]bool)
		c.all[v][Full] = true // all capabilities are effective in Full
		// all other ring types are false by default
	}

	err := c.getProc()
	if err != nil {
		return errfmt.WrapError(err)
	}

	for c := range c.all {
		err = cap.DropBound(c) // drop all capabilities from bound
		if err != nil {
			logger.Debugw("Dropping capability from bound", "cap", c, "error", err)
		}
	}

	err = c.setProc()
	if err != nil {
		return errfmt.WrapError(err)
	}

	// Add eBPF related capabilities to eBPF ring

	err = c.EBPFRingAdd(
		cap.IPC_LOCK,
		cap.SYS_RESOURCE,
	)
	if err != nil {
		logger.Fatalw("Adding initial capabilities to EBPF ring", "error", err)
	}

	// Kernels bellow v5.8 do not support cap.BPF + cap.PERFMON (instead of
	// having to have cap.SYS_ADMIN), nevertheless, some kernels, like RHEL8
	// clones, have backported cap.BPF capability and might be able to use it.

	paranoid, err := getKernelPerfEventParanoidValue()
	if err != nil {
		logger.Debugw("Could not get perf_event_paranoid, assuming highest", "error", err)
	}

	if paranoid > 2 {
		logger.Debugw("Paranoid: Value in /proc/sys/kernel/perf_event_paranoid is > 2")
		logger.Debugw("Paranoid: Tracee needs CAP_SYS_ADMIN instead of CAP_BPF + CAP_PERFMON")
		logger.Debugw("Paranoid: To change that behavior set perf_event_paranoid to 2 or less.")
		if err != nil {
			logger.Fatalw("Requiring capabilities", "error", err)
		}
	} else {
		logger.Debugw("Paranoid value", "value", paranoid)
	}

	hasBPF, _ := c.have.GetFlag(cap.Permitted, cap.BPF)
	if hasBPF {
		if paranoid < 2 {
			err = c.EBPFRingAdd(
				cap.BPF,
				cap.PERFMON,
			)
		} else {
			err = c.EBPFRingAdd(
				cap.SYS_ADMIN,
			)
		}
		if err != nil {
			logger.Fatalw("Adding eBPF capabilities to EBPF ring", "error", err)
		}
	} else {
		err = c.EBPFRingAdd(
			cap.SYS_ADMIN,
		)
		if err != nil {
			logger.Fatalw("Adding eBPF capabilities to EBPF ring", "error", err)
		}
	}

	return c.apply(Base) // Base ring is always effective
}

// Public Methods

func (c *Capabilities) Full(cb func() error) error {
	var err error

	if !c.bypass {
		c.lock.Lock()
		defer c.lock.Unlock()

		err = c.apply(Full) // move to ring Full
		if err != nil {
			return errfmt.WrapError(err)
		}
	}

	errCb := cb() // callback

	if !c.bypass {
		err = c.apply(Base) // back to ring Base
		if err != nil {
			return errfmt.WrapError(err)
		}
	}

	return errCb
}

func (c *Capabilities) EBPF(cb func() error) error {
	var err error

	if !c.bypass {
		c.lock.Lock()
		defer c.lock.Unlock()

		err = c.apply(EBPF) // move to ring EBPF
		if err != nil {
			return errfmt.WrapError(err)
		}
	}

	errCb := cb() // callback

	if !c.bypass {
		err = c.apply(Base) // back to ring Base
		if err != nil {
			return errfmt.WrapError(err)
		}
	}

	return errCb
}

func (c *Capabilities) Specific(cb func() error, values ...cap.Value) error {
	var err error

	if !c.bypass {
		c.lock.Lock()
		defer c.lock.Unlock()

		err = c.set(Specific, values...)
		if err != nil {
			return errfmt.WrapError(err)
		}
		err = c.apply(Specific) // move to ring Specific
		if err != nil {
			return errfmt.WrapError(err)
		}
		err = c.unset(Specific, values...) // clean specific ring for next calls
		if err != nil {
			return errfmt.WrapError(err)
		}
	}

	errCb := cb()
	if errCb != nil {
		logger.Debugw("Capabilities specific ring callback", "error", errCb)
	}

	if !c.bypass {
		err = c.apply(Base) // back to ring Base
		if err != nil {
			return errfmt.WrapError(err)
		}
	}

	return errCb
}

// setters/getters

func (c *Capabilities) EBPFRingAdd(values ...cap.Value) error {
	logger.Debugw("Adding capabilities to EBPF ring", "capability", values)

	return c.ringAdd(EBPF, values...)
}

func (c *Capabilities) EBPFRingRemove(values ...cap.Value) error {
	logger.Debugw("Removing capabilities from the EBPF ring", "capability", values)

	return c.ringRemove(EBPF, values...)
}

func (c *Capabilities) BaseRingAdd(values ...cap.Value) error {
	logger.Debugw("Adding capabilities to base ring", "capability", values)

	rings := []RingType{
		Base,
		EBPF,
		Specific,
	}

	for _, r := range rings {
		err := c.ringAdd(r, values...) // all rings should also have base caps
		if err != nil {
			return err
		}
	}

	// immediate effect (always called from the Base ring context)
	return c.apply(Base)
}

func (c *Capabilities) BaseRingRemove(values ...cap.Value) error {
	logger.Debugw("Removing capabilities from the base ring", "capability", values)

	rings := []RingType{
		Base,
		EBPF,
		Specific,
	}

	for _, r := range rings {
		err := c.ringRemove(r, values...) // all rings should have same base caps
		if err != nil {
			return err
		}
	}

	// immediate effect (always called from the Base ring context)
	return c.apply(Base)
}

// Private Methods

func (c *Capabilities) ringAdd(ring RingType, values ...cap.Value) error {
	var err error

	if c.bypass {
		return nil
	}

	c.lock.Lock()
	err = c.set(ring, values...)
	c.lock.Unlock()

	return errfmt.WrapError(err)
}

func (c *Capabilities) ringRemove(ring RingType, values ...cap.Value) error {
	var err error

	if c.bypass {
		return nil
	}

	c.lock.Lock()
	err = c.unset(ring, values...)
	c.lock.Unlock()

	return errfmt.WrapError(err)
}

func (c *Capabilities) getProc() error {
	var err error

	c.have, err = cap.GetPID(0)
	if err != nil {
		return couldNotGetProc(err)
	}

	return nil
}

func (c *Capabilities) setProc() error {
	err := c.have.SetProc()
	if err != nil {
		return couldNotSetProc(err)
	}

	return nil
}

func (c *Capabilities) set(t RingType, values ...cap.Value) error {
	for _, v := range values {
		c.all[v][t] = true
	}

	return nil
}

func (c *Capabilities) unset(t RingType, values ...cap.Value) error {
	for _, v := range values {
		c.all[v][t] = false
	}

	return nil
}

func (c *Capabilities) apply(t RingType) error {
	var err error

	err = c.getProc()
	if err != nil {
		return errfmt.WrapError(err)
	}

	logger.Debugw("Capabilities change")

	for k, v := range c.all {
		if v[t] {
			logger.Debugw("Enabling cap", "cap", k)
		}
		err = c.have.SetFlag(cap.Effective, v[t], k)
		if err != nil {
			return errfmt.WrapError(err)
		}
	}

	return c.setProc()
}

//
// Error Functions
//

func couldNotFindCapability(cap string) error {
	return fmt.Errorf("could not find capability: %v", cap)
}

func couldNotReadPerfEventParanoid() error {
	return fmt.Errorf("could not read procfs perf_event_paranoid")
}

func couldNotSetProc(e error) error {
	return fmt.Errorf("could not set capabilities: %v", e)
}

func couldNotGetProc(e error) error {
	return fmt.Errorf("could not get capabilities: %v", e)
}

//
// Standalone Functions
//

func ReqByString(values ...string) ([]cap.Value, error) {
	var found bool
	var capsToActOn []cap.Value

	for _, given := range values {
		found = false
		for v := cap.Value(0); v < cap.MaxBits(); v++ {
			if v.String() == given {
				capsToActOn = append(capsToActOn, v)
				found = true
			}
		}
		if !found {
			return nil, couldNotFindCapability(given)
		}
	}

	return capsToActOn, nil
}

// ListAvailCaps lists available capabilities in the running environment
func ListAvailCaps() []string {
	var availCaps []string

	for v := cap.Value(0); v < cap.MaxBits(); v++ {
		availCaps = append(availCaps, v.String())
	}

	return availCaps
}

// getKernelPerfEventParanoidValue retrieves the value of the kernel parameter
// perf_event_paranoid
func getKernelPerfEventParanoidValue() (int, error) {
	// perf event paranoia level:
	//
	// -1 = not paranoid at all
	//  0 = disallow raw tracepoint access for unpriv
	//  1 = disallow cpu events for unpriv
	//  2 = disallow kernel profiling for unpriv
	//  4 = disallow all unpriv perf event use (not in all distros)
	//
	const MaxParanoiaLevel = 4

	value, err := os.ReadFile("/proc/sys/kernel/perf_event_paranoid")
	if err != nil {
		return MaxParanoiaLevel, couldNotReadPerfEventParanoid()
	}

	intVal, err := strconv.ParseInt(strings.TrimSuffix(string(value), "\n"), 0, 16)
	if err != nil {
		return MaxParanoiaLevel, couldNotReadPerfEventParanoid()
	}

	return int(intVal), nil
}
