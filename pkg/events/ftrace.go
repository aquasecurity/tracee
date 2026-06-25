package events

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"kernel.org/pub/linux/libs/security/libcap/cap"

	"github.com/aquasecurity/tracee/common/capabilities"
	"github.com/aquasecurity/tracee/common/logger"
	"github.com/aquasecurity/tracee/common/timeutil"
	"github.com/aquasecurity/tracee/types/trace"
)

const (
	sysKernelPrefix      = "/sys/kernel/"
	sysKernelDebugPrefix = sysKernelPrefix + "debug/"
)

const (
	symbolIndex = iota
	trampIndex
	callbackFuncIndex
	callbackOffsetIndex
	callbackOwnerIndex
	flagsIndex
	countIndex
)

var (
	reportedFtraceHooks *lru.Cache[string, reportedFtraceHook]
	FtraceWakeupChan    = make(chan struct{})
)

func init() {
	var err error
	reportedFtraceHooks, err = lru.New[string, reportedFtraceHook](2048)
	if err != nil {
		logger.Errorw("ftrace: failed allocating cache... stopping")
		reportedFtraceHooks = nil
	}
}

// GetFtraceBaseEvent creates an ftrace hook event with basic common fields
func GetFtraceBaseEvent() *trace.Event {
	ftraceHookBaseEvent := &trace.Event{
		ProcessName: "tracee",
		EventID:     int(FtraceHook),
		EventName:   Core.GetDefinitionByID(FtraceHook).GetName(),
	}

	return ftraceHookBaseEvent
}

// FtraceHookEvent check for ftrace hooks periodically and reports them.
// It wakes up every random time to check if there was a change in the hooks.
// The caller must call wg.Add(1) before launching this goroutine; wg.Done()
// is called when the goroutine exits, allowing the caller to wait before
// closing the out channel.
func FtraceHookEvent(ctx context.Context, wg *sync.WaitGroup, out chan *PipelineEvent, baseEvent *trace.Event, selfLoadedProgs map[string]int) {
	defer wg.Done()
	logger.Debugw("Starting ftraceHook goroutine")
	defer logger.Debugw("Stopped ftraceHook goroutine")

	if reportedFtraceHooks == nil { // Failed allocating cache - no point in running
		return
	}

	def := Core.GetDefinitionByID(FtraceHook)

	// Trigger from time to time or on demand
	for {
		// bail before starting a scan if a wakeup and
		// ctx cancellation raced in the wait select below,
		// avoiding the initial sysfs read on shutdown.
		if ctx.Err() != nil {
			return
		}

		err := checkFtraceHooks(ctx, out, baseEvent, &def, selfLoadedProgs)
		if err != nil {
			// Context cancelled - exit gracefully
			if ctx.Err() != nil {
				return
			}
			logger.Errorw("error occurred checking ftrace hooks", "error", err)
		}

		select {
		case <-ctx.Done():
			return
		case <-FtraceWakeupChan:
		case <-time.After(timeutil.GenerateRandomDuration(10, 300)):
		}
	}
}

// readSysKernelFile reads a sysfs file. path is the suffix after /sys/kernel/
// (e.g. "tracing/enabled_functions"). It tries /sys/kernel/<path> first; if
// that file is missing, it falls back to /sys/kernel/debug/<path> for kernels
// where tracing is only exposed under debugfs. Requires cap.SYSLOG.
func readSysKernelFile(path string) ([]byte, error) {
	var data []byte
	err := capabilities.GetInstance().Specific(
		func() error {
			var innerErr error
			data, innerErr = os.ReadFile(sysKernelPrefix + path)
			if innerErr != nil {
				data, innerErr = os.ReadFile(sysKernelDebugPrefix + path)
				if innerErr != nil {
					return innerErr
				}
			}
			return nil
		},
		cap.SYSLOG,
	)

	if err != nil {
		return nil, err
	}

	return data, nil
}

// getFtraceHooksData gets ftrace hooks related data from file
func getFtraceHooksData() ([]byte, error) {
	data, err := readSysKernelFile("tracing/enabled_functions")
	return data, err
}

// buildFtraceArgs materializes the reported event arguments from a parsed hook.
// It is only called when a hook is actually reported, so the per-line parse path
// avoids the []trace.Argument allocation and interface boxing entirely.
func buildFtraceArgs(fields []DataField, hook reportedFtraceHook) []trace.Argument {
	return []trace.Argument{
		{ArgMeta: fields[symbolIndex].ArgMeta, Value: hook.symbol},
		{ArgMeta: fields[trampIndex].ArgMeta, Value: hook.trampoline},
		{ArgMeta: fields[callbackFuncIndex].ArgMeta, Value: hook.callbackFunc},
		{ArgMeta: fields[callbackOffsetIndex].ArgMeta, Value: int64(hook.callbackOffset)},
		{ArgMeta: fields[callbackOwnerIndex].ArgMeta, Value: hook.callbackOwner},
		{ArgMeta: fields[flagsIndex].ArgMeta, Value: hook.flags.String()},
		{ArgMeta: fields[countIndex].ArgMeta, Value: int(hook.count)},
	}
}

// ftraceFlags is a compact bitmask of the per-hook flag characters the kernel
// prints in the enabled_functions "flags" column, stored as a single byte instead
// of a string. The bits are declared in the kernel's fixed emission order
// (R, I, D, O, M - matching the FTRACE_FL_* order in t_show), so String()
// reproduces the original flags column exactly.
type ftraceFlags uint8

const (
	ftraceFlagRegs     ftraceFlags = 1 << iota // R: FTRACE_FL_REGS
	ftraceFlagIPModify                         // I: FTRACE_FL_IPMODIFY
	ftraceFlagDirect                           // D: FTRACE_FL_DIRECT
	ftraceFlagCallOps                          // O: FTRACE_FL_CALL_OPS
	ftraceFlagModified                         // M: FTRACE_FL_MODIFIED
)

// String renders the flags back to the kernel's textual form (e.g. "RID"),
// emitting characters in the kernel's fixed order so the output matches the
// original enabled_functions column. Returns "" when no flags are set.
func (f ftraceFlags) String() string {
	var buf [5]byte
	n := 0

	for _, fc := range []struct {
		bit ftraceFlags
		c   byte
	}{
		{ftraceFlagRegs, 'R'},
		{ftraceFlagIPModify, 'I'},
		{ftraceFlagDirect, 'D'},
		{ftraceFlagCallOps, 'O'},
		{ftraceFlagModified, 'M'},
	} {
		if f&fc.bit != 0 {
			buf[n] = fc.c
			n++
		}
	}

	return string(buf[:n])
}

// reportedFtraceHook is a compact snapshot of a reported hook kept in the dedup LRU.
// It holds only the reportable values (mirroring the *Index args) and drops
// the constant ArgMeta and interface boxing carried by []trace.Argument, so each
// long-lived cache entry stays small. All fields are comparable.
//
// Field order is deliberate: the string headers (8-byte aligned) come first, the
// two int32 numeric fields are grouped next so they share a single 8-byte slot,
// and the 1-byte flags bitmask trails them (80 bytes total). count and offset are
// int32 because both hold small values and flags is a uint8 bitmask;
// buildFtraceArgs converts them back to the int/int64/string the event arguments
// expose. callbackOffset is an in-function displacement (always < the function
// size, i.e. KB-scale), so it fits int32 with ~5 orders of magnitude of headroom
// (overflow would require a >2 GiB function); parseFtraceHook guards the narrowing.
type reportedFtraceHook struct {
	symbol         string
	trampoline     string
	callbackFunc   string
	callbackOwner  string
	count          int32
	callbackOffset int32
	flags          ftraceFlags
}

// detach returns a copy whose strings are cloned off the source buffer, so a
// long-lived LRU entry doesn't pin the large enabled_functions contents.
func (h reportedFtraceHook) detach() reportedFtraceHook {
	h.symbol = strings.Clone(h.symbol)
	h.trampoline = strings.Clone(h.trampoline)
	h.callbackFunc = strings.Clone(h.callbackFunc)
	h.callbackOwner = strings.Clone(h.callbackOwner)
	return h
}

// checkFtraceHooks checks for ftrace hooks
func checkFtraceHooks(ctx context.Context, out chan *PipelineEvent, baseEvent *trace.Event, ftraceDef *Definition, selfLoadedProgs map[string]int) error {
	ftraceHooksBytes, err := getFtraceHooksData()
	if err != nil {
		return err
	}

	// Read tracee's own kprobe list once per scan (instead of once per hooked
	// symbol) to know how many ftrace-based kprobes tracee itself installed on
	// each symbol. Only needed when tracee self-loaded programs exist.
	var kprobeFtraceCounts map[string]int
	if len(selfLoadedProgs) > 0 {
		kprobeData, err := readSysKernelFile("kprobes/list")
		if err != nil {
			return err
		}
		kprobeFtraceCounts = parseKprobeFtraceCounts(kprobeData)
	}

	directArg := false // Direct arg flag

	for ftraceLine := range strings.SplitSeq(string(ftraceHooksBytes), "\n") {
		// Check for context cancellation early to avoid unnecessary work
		if ctx.Err() != nil {
			return ctx.Err()
		}

		if len(ftraceLine) == 0 {
			continue
		}

		if directArg && strings.HasPrefix(ftraceLine, "\tdirect-->") {
			directArg = false // Turn off flag
			continue
		}

		ftraceLine = strings.ReplaceAll(ftraceLine, "\t", " ")

		// Parse into a typed snapshot (no interface boxing / args allocation on
		// the per-line path); the full []trace.Argument is built only on report.
		hook, err := parseFtraceHook(ftraceLine)
		if err != nil {
			return err
		}

		if hook.flags&ftraceFlagDirect != 0 {
			// On some kernels, a line follows after a hook with D (direct) parameter. Prepare to skip it.
			directArg = true // To be used in the next line (next iteration)
		}

		causedByTracee, newCount := isCausedBySelfLoadedProg(selfLoadedProgs, kprobeFtraceCounts, hook.symbol, int(hook.count))
		if causedByTracee {
			continue
		}

		hook.count = int32(newCount)

		// Verify that we didn't report this symbol already, and it wasn't changed.
		// If we reported the symbol in the past, and now the count has reduced - report only if the callback was changed
		if existing, found := reportedFtraceHooks.Get(hook.symbol); found {
			if existing == hook ||
				(hook.count < existing.count && hook.callbackFunc == existing.callbackFunc) {
				continue
			}
		}

		// Store a detached copy so the long-lived cache entry doesn't pin the
		// large enabled_functions buffer the hook's strings point into.
		stored := hook.detach()
		reportedFtraceHooks.Add(stored.symbol, stored) // Mark that we're reporting this hook, so we won't report it multiple times

		// Materialize the full args only now that we're actually reporting.
		event := *baseEvent // shallow copy
		event.Timestamp = int(time.Now().UnixNano())
		event.Args = buildFtraceArgs(ftraceDef.GetFields(), hook)
		event.ArgsNum = len(event.Args)

		// Safe to send: processEvents waits for our WaitGroup before
		// closing the out channel, so out is guaranteed to be open.
		out <- NewPipelineEvent(&event)
	}

	return nil
}

// isCausedBySelfLoadedProg checks if the hook is caused solely by tracee.
// Returns the effective count taking into consideration the hooks by tracee and ftrace based k[ret]probes.
// kprobeFtraceCounts maps each symbol to the number of ftrace-based kprobes installed on it (see
// parseKprobeFtraceCounts); it is built once per scan and may be nil when tracee self-loaded no programs.
func isCausedBySelfLoadedProg(selfLoadedProgs, kprobeFtraceCounts map[string]int, symbol string, oldCount int) (bool, int) {
	numHooksFromTracee, found := selfLoadedProgs[symbol]
	if !found {
		return false, oldCount
	}

	// Tracee uses this hook
	// In case of k[ret]probe, there might be multiple hooks on same symbol and the ftrace count will still be 1.
	numKprobes := kprobeFtraceCounts[symbol]

	newCount := oldCount
	if oldCount != 1 { // Someone else must be hooking using ftrace since tracee only causes 1 ftrace hook
		newCount = oldCount - 1 + (numKprobes - numHooksFromTracee) // Reduce count caused by tracee and add the number of k[ret]probes (other than tracee's)
	} else {
		if numKprobes == numHooksFromTracee { // count is 1 and all k[ret]probes are caused by us... there's nothing to report
			return true, -1
		}

		newCount = numKprobes - numHooksFromTracee // The amount of k[ret]probes other than tracee's
	}

	return false, newCount
}

// parseFtraceHook parses a single (tab-normalized) enabled_functions line into a
// reportedFtraceHook snapshot, parsing into typed fields to avoid the interface
// boxing of []trace.Argument on every line.
func parseFtraceHook(ftraceLine string) (reportedFtraceHook, error) {
	ftraceParts := strings.Split(ftraceLine, " ")

	if len(ftraceParts) < 4 {
		return reportedFtraceHook{}, errors.New("ftrace: unexpected format of file... " + ftraceLine)
	}

	hook := reportedFtraceHook{symbol: ftraceParts[0]}

	// ParseInt with bitSize 32 errors on overflow, so the result fits int32 safely.
	count, err := strconv.ParseInt(ftraceParts[1][1:len(ftraceParts[1])-1], 10, 32) // Remove parenthesis
	if err != nil {
		return reportedFtraceHook{}, err
	}
	hook.count = int32(count)

	index := 2

	hook.flags = getFtraceFlags(ftraceParts, &index)

	var callback string
	hook.trampoline, callback = fetchTrampAndCallback(ftraceParts, &index)
	var callbackOffset int64
	hook.callbackFunc, callbackOffset, hook.callbackOwner = splitCallback(callback)
	// callbackOffset is an in-function displacement (bounded by the function
	// size), so it always fits int32 in practice; guard against silent
	// truncation on unexpected/malformed input rather than storing a wrong value.
	if callbackOffset > math.MaxInt32 {
		return reportedFtraceHook{}, fmt.Errorf("ftrace: callback offset 0x%x exceeds int32 range", callbackOffset)
	}
	hook.callbackOffset = int32(callbackOffset)

	return hook, nil
}

type dupSymbolEntry struct {
	name     string
	hookType string
}

// parseKprobeFtraceCounts parses the kprobe list once and returns, per symbol, the number of
// ftrace-based kprobes installed on it. Reading and parsing the file a single time per scan
// avoids the previous O(symbols x file) cost of re-reading it for every hooked symbol.
//
// The kprobe list file may have the following formats:
// c015d71a  k  vfs_read+0x0
// c015d71a  r  vfs_read+0x0 [FTRACE]
//
// There may be multiple symbols at different addresses in the kernel. When attaching a hook on
// such a symbol, the kernel attaches multiple kprobes at those locations:
// ffffffff9fd44d20  k  load_elf_phdrs+0x0    [FTRACE]
// ffffffff9fd47b60  k  load_elf_phdrs+0x0    [FTRACE]
// so we deduplicate per (symbol, hookType): the first address seen counts, and subsequent lines
// only count when they repeat that same address (avoiding counting distinct locations as separate probes).
func parseKprobeFtraceCounts(data []byte) map[string]int {
	counts := map[string]int{}
	firstAddr := map[dupSymbolEntry]string{}

	for kprobeLine := range strings.SplitSeq(string(data), "\n") {
		if len(kprobeLine) == 0 {
			continue
		}

		lineSplit := strings.Fields(kprobeLine)
		// Need at least: address, type, symbol+offset, and a [FTRACE] status.
		if len(lineSplit) < 4 {
			continue
		}

		addr := lineSplit[0]
		hookType := lineSplit[1]

		plusIdx := strings.Index(lineSplit[2], "+")
		if plusIdx == -1 {
			continue // unexpected format: no symbol+offset
		}
		symbol := lineSplit[2][:plusIdx]

		// Verify this is an ftrace based kprobe
		isFtrace := false
		for _, status := range lineSplit[3:] {
			if status == "[FTRACE]" {
				isFtrace = true
				break
			}
		}
		if !isFtrace {
			continue
		}

		key := dupSymbolEntry{name: symbol, hookType: hookType}
		countedSymbolAddr, found := firstAddr[key]
		if !found {
			firstAddr[key] = addr
			counts[symbol]++
		} else if addr == countedSymbolAddr {
			// Same address - multiple hooks on same symbol - increment counter
			counts[symbol]++
		}
	}

	return counts
}

// splitCallback splits it into separate parts
// callback can be of 3 forms:
// - some_func+0x0/0x10 [rootkit]
// - some_func+0x0/0x10
// - 0xffffffffc0637000
// The returned offset is the callback's displacement within its function (the
// value between '+' and '/', e.g. 0x1d0), bounded by the function size; it is 0
// for the bare-address form and -1 when the offset cannot be parsed.
func splitCallback(callback string) (string, int64, string) {
	index := strings.Index(callback, "+")
	if index == -1 {
		return callback, 0, "" // Looks like the symbol wasn't resolved and stayed as an address
	}
	funcName := callback[:index]

	slashOffset := strings.Index(callback, "/")

	offset, err := strconv.ParseInt(callback[index+1 : slashOffset][2:], 16, 64)
	if err != nil {
		logger.Debugw(err.Error())
		return funcName, -1, ""
	}

	startOwnerOffset := strings.Index(callback, "[")
	if startOwnerOffset == -1 {
		return funcName, offset, ""
	}

	// If it contains '[', it must contain the closing ']'
	owner := callback[startOwnerOffset+1 : strings.Index(callback, "]")]

	return funcName, offset, owner
}

// revive:disable:confusing-results

// fetchTrampAndCallback extracts the trampoline and the callback
func fetchTrampAndCallback(ftraceParts []string, i *int) (string, string) {
	trampoline := ""
	callback := ""

	for ; *i < len(ftraceParts); *i++ {
		currWord := strings.TrimLeft(ftraceParts[*i], "\t")

		if currWord == "tramp:" && ftraceParts[(*i)+1] != "ERROR!" {
			trampoline = ftraceParts[(*i)+1]
			callback = getCallback(ftraceParts[(*i)+2:])
			break
		} else if currWord == "ops:" && ftraceParts[(*i)+1] != "ERROR!" {
			callback = getCallback(ftraceParts[(*i)+2:])
			break
		} else if strings.HasPrefix(currWord, "->") {
			callback = currWord[2:] // remove '->'
			break
		} else if strings.HasPrefix(ftraceParts[*i], "direct-->") {
			callback = currWord[9:] // remove 'direct-->'
			break
		}
	}

	return trampoline, callback
}

// revive:enable:confusing-results

// getCallback extracts the callback
func getCallback(ftraceParts []string) string {
	callback := ftraceParts[0][1:] // Remove left parenthesis

	if strings.HasSuffix(callback, ")") {
		callback = callback[:len(callback)-1]
	} else {
		callback += ftraceParts[1][:len(ftraceParts[1])-1] // Get the rest of the callback and remove the right parenthesis
	}

	return callback
}

// getFtraceFlags extracts the flag bitmask, advancing *index to the first token
// past the flags section (matching the previous break-on-non-flag behavior so
// fetchTrampAndCallback resumes at the right token). The caller derives the
// direct-hook signal from the returned ftraceFlagDirect bit.
func getFtraceFlags(ftraceParts []string, index *int) ftraceFlags {
	var flags ftraceFlags
	for ; *index < len(ftraceParts); *index++ {
		flag := strings.TrimSpace(ftraceParts[*index])
		if flag == "" {
			continue
		}

		switch flag {
		case "R":
			flags |= ftraceFlagRegs
		case "I":
			flags |= ftraceFlagIPModify
		case "D":
			flags |= ftraceFlagDirect
		case "O":
			flags |= ftraceFlagCallOps
		case "M":
			flags |= ftraceFlagModified
		default:
			// Reached the end of the flags section; leave *index here.
			return flags
		}
	}

	return flags
}
