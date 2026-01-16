// Package capabilities provides a ring-based Linux capabilities management system
// for Tracee. It implements a singleton pattern to manage process capabilities
// through different execution protection rings:
//
//   - Full: All capabilities are effective (least secure)
//   - EBPF: eBPF needed capabilities + Base capabilities
//   - Specific: Specific requested capabilities + Base capabilities
//   - Base: Capabilities that are always effective (most secure)
//
// The package supports a bypass mode (Bypass=true) where capability changes
// are tracked in memory but not applied to the actual process, allowing
// testing and development without root privileges.
package capabilities

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"kernel.org/pub/linux/libs/security/libcap/cap"

	"github.com/aquasecurity/tracee/common/errfmt"
	"github.com/aquasecurity/tracee/common/logger"
)

var caps *Capabilities   // singleton for all packages
var capsMutex sync.Mutex // mutex to protect access to caps
var once sync.Once

// RingType represents the execution protection ring level for capabilities.
// Rings provide different levels of capability access, with Base being the
// most restrictive and Full being the least restrictive.
type RingType int

const (
	// Full ring enables all capabilities. This is the least secure mode
	// and should only be used when necessary.
	Full RingType = iota

	// EBPF ring enables eBPF-related capabilities plus base capabilities.
	// Used for eBPF operations that require specific Linux capabilities.
	EBPF

	// Specific ring enables only the requested capabilities plus base capabilities.
	// Used for operations that need temporary access to specific capabilities.
	Specific

	// Base ring contains capabilities that are always effective.
	// This is the default and most secure ring.
	Base
)

// Capabilities manages Linux capabilities through a ring-based execution model.
// It provides methods to temporarily elevate capabilities for specific operations
// and automatically return to the base ring afterward.
//
// The struct uses a singleton pattern and should be accessed via GetInstance()
// or Initialize(). When Bypass is true, capability changes are tracked in memory
// but not applied to the actual process.
type Capabilities struct {
	have     *cap.Set
	all      map[cap.Value]map[RingType]bool
	bypass   bool
	baseEbpf bool
	lock     *sync.Mutex // big lock to guarantee all threads are on the same ring
}

// Config holds configuration options for initializing the capabilities manager.
type Config struct {
	// Bypass, when true, disables actual capability changes and operates
	// entirely in memory. Useful for testing and development without root.
	Bypass bool

	// BaseEbpf, when true, adds eBPF-related capabilities to the base ring
	// instead of the eBPF ring. This means eBPF capabilities are always
	// available without needing to switch to the EBPF ring.
	BaseEbpf bool
}

// initializeOnce performs the actual singleton initialization without external locking.
// This function should only be called while holding capsMutex.
func initializeOnce(cfg Config) error {
	var err error

	once.Do(func() {
		caps = &Capabilities{
			lock: new(sync.Mutex),
		}
		caps.lock.Lock()
		defer caps.lock.Unlock()

		err = caps.initialize(cfg)
	})

	return errfmt.WrapError(err)
}

// Initialize initializes the capabilities singleton instance with the given configuration.
// This function is thread-safe and will only initialize once, even if called multiple times.
//
// When Bypass is true, the capabilities manager operates in bypass mode where
// capability changes are tracked but not applied to the process.
//
// Returns an error if initialization fails (e.g., unable to read process capabilities
// when Bypass is false).
func Initialize(cfg Config) error {
	capsMutex.Lock()
	defer capsMutex.Unlock()

	return initializeOnce(cfg)
}

// GetInstance returns the current capabilities instance, initializing it if needed.
// If the instance doesn't exist, it auto-initializes with Bypass=true and BaseEbpf=false.
//
// This is the recommended way to access the capabilities manager for most use cases.
// Returns nil if initialization fails.
func GetInstance() *Capabilities {
	capsMutex.Lock()
	defer capsMutex.Unlock()

	if caps == nil {
		err := initializeOnce(Config{
			Bypass:   true,
			BaseEbpf: false,
		})
		if err != nil {
			return nil
		}
	}

	return caps
}

func (c *Capabilities) initialize(cfg Config) error {
	c.bypass = cfg.Bypass
	c.baseEbpf = cfg.BaseEbpf

	// Always initialize internal state map, even in bypass mode
	// Bypass only affects system calls in apply(), not state tracking
	c.all = make(map[cap.Value]map[RingType]bool)

	for v := cap.Value(0); v < cap.MaxBits(); v++ {
		c.all[v] = make(map[RingType]bool)
		c.all[v][Full] = true // all capabilities are effective in Full
		// all other ring types are false by default
	}

	// Add eBPF related capabilities to eBPF ring (always update state)
	if c.baseEbpf {
		err := c.baseRingAdd(
			cap.IPC_LOCK,
			cap.SYS_RESOURCE,
		)
		if err != nil {
			logger.Fatalw("Adding initial capabilities to EBPF ring", "error", err)
		}
	} else {
		err := c.eBPFRingAdd(
			cap.IPC_LOCK,
			cap.SYS_RESOURCE,
		)
		if err != nil {
			logger.Fatalw("Adding initial capabilities to EBPF ring", "error", err)
		}
	}

	// In bypass mode, skip system calls but keep state initialized
	if c.bypass {
		return nil
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
			if c.baseEbpf {
				err = c.baseRingAdd(
					cap.BPF,
					cap.PERFMON,
				)
			} else {
				err = c.eBPFRingAdd(
					cap.BPF,
					cap.PERFMON,
				)
			}
		} else {
			if c.baseEbpf {
				err = c.baseRingAdd(
					cap.SYS_ADMIN,
				)
			} else {
				err = c.eBPFRingAdd(
					cap.SYS_ADMIN,
				)
			}
		}
		if err != nil {
			logger.Fatalw("Adding eBPF capabilities to EBPF ring", "error", err)
		}
	} else {
		if c.baseEbpf {
			err = c.baseRingAdd(
				cap.SYS_ADMIN,
			)
		} else {
			err = c.eBPFRingAdd(
				cap.SYS_ADMIN,
			)
		}
		if err != nil {
			logger.Fatalw("Adding eBPF capabilities to EBPF ring", "error", err)
		}
	}

	return c.apply(Base) // Base ring is always effective
}

// Full temporarily elevates to the Full ring (all capabilities enabled),
// executes the callback, then returns to the Base ring.
//
// When bypass mode is enabled, this method executes the callback without
// actually changing capabilities.
//
// The callback's error is returned. If an error occurs during ring switching,
// it is wrapped and returned.
func (c *Capabilities) Full(cb func() error) error {
	var err error

	c.lock.Lock()
	defer c.lock.Unlock()

	err = c.apply(Full) // move to ring Full
	if err != nil {
		return errfmt.WrapError(err)
	}

	errCb := cb() // callback

	err = c.apply(Base) // back to ring Base
	if err != nil {
		return errfmt.WrapError(err)
	}

	return errCb
}

// EBPF temporarily elevates to the EBPF ring (eBPF capabilities + base),
// executes the callback, then returns to the Base ring.
//
// When baseEbpf is true, this method executes the callback without switching
// rings (since eBPF caps are already available). In bypass mode, system calls
// are skipped but state tracking continues.
//
// The callback's error is returned. If an error occurs during ring switching,
// it is wrapped and returned.
func (c *Capabilities) EBPF(cb func() error) error {
	var err error

	c.lock.Lock()
	defer c.lock.Unlock()

	if !c.baseEbpf {
		err = c.apply(EBPF) // move to ring EBPF
		if err != nil {
			return errfmt.WrapError(err)
		}
	}

	errCb := cb() // callback

	if !c.baseEbpf {
		err = c.apply(Base) // back to ring Base
		if err != nil {
			return errfmt.WrapError(err)
		}
	}

	return errCb
}

// Specific temporarily enables the specified capabilities in the Specific ring,
// executes the callback, then returns to the Base ring and cleans up the Specific ring.
//
// The Specific ring is cleaned up before the callback executes (internal state only).
// The process capabilities remain active during the callback, but the internal state
// is cleared to ensure it doesn't affect subsequent calls. In bypass mode,
// system calls are skipped but state tracking continues.
//
// The callback's error is returned. If an error occurs during ring operations,
// it is wrapped and returned.
func (c *Capabilities) Specific(cb func() error, values ...cap.Value) error {
	var err error

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

	errCb := cb()
	if errCb != nil {
		logger.Debugw("Capabilities specific ring callback", "error", errCb)
	}

	err = c.apply(Base) // back to ring Base
	if err != nil {
		return errfmt.WrapError(err)
	}

	return errCb
}

// EBPFRingAdd adds the specified capabilities to the EBPF ring.
// These capabilities will be available when switching to the EBPF ring.
//
// Returns an error if any of the specified capabilities are invalid.
func (c *Capabilities) EBPFRingAdd(values ...cap.Value) error {
	c.lock.Lock()
	defer c.lock.Unlock()

	return c.eBPFRingAdd(values...)
}

// EBPFRingRemove removes the specified capabilities from the EBPF ring.
// These capabilities will no longer be available when switching to the EBPF ring.
//
// Returns an error if any of the specified capabilities are invalid.
func (c *Capabilities) EBPFRingRemove(values ...cap.Value) error {
	c.lock.Lock()
	defer c.lock.Unlock()

	return c.eBPFRingRemove(values...)
}

// BaseRingAdd adds the specified capabilities to the base ring and propagates
// them to all other rings (EBPF and Specific). Base ring capabilities are
// always effective regardless of the current ring.
//
// Internal state is always updated and changes are immediately applied.
// In bypass mode, system calls are skipped but state tracking continues.
// Returns an error if any of the specified capabilities are invalid.
func (c *Capabilities) BaseRingAdd(values ...cap.Value) error {
	c.lock.Lock()
	defer c.lock.Unlock()

	return c.baseRingAdd(values...)
}

// BaseRingRemove removes the specified capabilities from the base ring and
// all other rings (EBPF and Specific). Base ring capabilities are always effective,
// so removing them affects all rings.
//
// Internal state is always updated and changes are immediately applied.
// In bypass mode, system calls are skipped but state tracking continues.
// Returns an error if any of the specified capabilities are invalid.
func (c *Capabilities) BaseRingRemove(values ...cap.Value) error {
	c.lock.Lock()
	defer c.lock.Unlock()

	return c.baseRingRemove(values...)
}

func (c *Capabilities) eBPFRingAdd(values ...cap.Value) error {
	logger.Debugw("Adding capabilities to EBPF ring", "capability", values)

	return c.ringAdd(EBPF, values...)
}

func (c *Capabilities) eBPFRingRemove(values ...cap.Value) error {
	logger.Debugw("Removing capabilities from the EBPF ring", "capability", values)

	return c.ringRemove(EBPF, values...)
}

func (c *Capabilities) baseRingAdd(values ...cap.Value) error {
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

func (c *Capabilities) baseRingRemove(values ...cap.Value) error {
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

func (c *Capabilities) ringAdd(ring RingType, values ...cap.Value) error {
	// Always update internal state - bypass only affects system calls in apply()
	return errfmt.WrapError(c.set(ring, values...))
}

func (c *Capabilities) ringRemove(ring RingType, values ...cap.Value) error {
	// Always update internal state - bypass only affects system calls in apply()
	return errfmt.WrapError(c.unset(ring, values...))
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
		m, exists := c.all[v]
		if !exists {
			return fmt.Errorf("failed to set capability %v: not supported", v)
		}
		m[t] = true
	}
	return nil
}

func (c *Capabilities) unset(t RingType, values ...cap.Value) error {
	for _, v := range values {
		m, exists := c.all[v]
		if !exists {
			return fmt.Errorf("failed to unset capability %v: not supported", v)
		}
		m[t] = false
	}
	return nil
}

func (c *Capabilities) apply(t RingType) error {
	// In bypass mode, skip actual system calls but still track state changes
	if c.bypass {
		logger.Debugw("Capabilities change (bypass mode)", "ring", t)
		return nil
	}

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

func couldNotFindCapability(c string) error {
	return fmt.Errorf("could not find capability: %v", c)
}

func couldNotReadPerfEventParanoid() error {
	return errors.New("could not read procfs perf_event_paranoid")
}

func couldNotSetProc(e error) error {
	return fmt.Errorf("could not set capabilities: %v", e)
}

func couldNotGetProc(e error) error {
	return fmt.Errorf("could not get capabilities: %v", e)
}

// ReqByString converts capability string names to cap.Value types.
// It accepts one or more capability names (e.g., "CAP_SYS_ADMIN", "CAP_NET_ADMIN")
// and returns the corresponding cap.Value slice.
//
// Returns an error if any of the provided capability names are invalid or not found.
// Example:
//
//	values, err := ReqByString("CAP_SYS_ADMIN", "CAP_NET_ADMIN")
//	if err != nil {
//	    return err
//	}
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
	const maxParanoiaLevel = 4

	value, err := os.ReadFile("/proc/sys/kernel/perf_event_paranoid")
	if err != nil {
		return maxParanoiaLevel, couldNotReadPerfEventParanoid()
	}

	intVal, err := strconv.ParseInt(strings.TrimSuffix(string(value), "\n"), 0, 16)
	if err != nil {
		return maxParanoiaLevel, couldNotReadPerfEventParanoid()
	}

	return int(intVal), nil
}
