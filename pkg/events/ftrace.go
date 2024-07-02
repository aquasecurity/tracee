package events

import (
	"errors"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"kernel.org/pub/linux/libs/security/libcap/cap"

	"github.com/aquasecurity/tracee/pkg/capabilities"
	"github.com/aquasecurity/tracee/pkg/counter"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/utils"
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
	reportedFtraceHooks *lru.Cache[string, []trace.Argument]
	FtraceWakeupChan    = make(chan struct{})
)

func init() {
	var err error
	reportedFtraceHooks, err = lru.New[string, []trace.Argument](2048)
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
func FtraceHookEvent(eventsCounter counter.Counter, out chan *trace.Event, baseEvent *trace.Event, selfLoadedProgs map[string]int) {
	if reportedFtraceHooks == nil { // Failed allocating cache - no point in running
		return
	}

	def := Core.GetDefinitionByID(FtraceHook)

	// Trigger from time to time or on demand
	for {
		err := checkFtraceHooks(eventsCounter, out, baseEvent, &def, selfLoadedProgs)
		if err != nil {
			logger.Errorw("error occurred checking ftrace hooks", "error", err)
		}

		select {
		case <-FtraceWakeupChan:
		case <-time.After(utils.GenerateRandomDuration(10, 300)):
		}
	}
}

// readSysKernelFile gets file data corresponding to a path. The path should be what is after /sys/kernel/. If initial path not found, checks for
// the path with /sys/kernel/debug for older kernels.
// Assumes debugfs is mounted under /sys/kernel/debug
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

func initFtraceArgs(params []trace.ArgMeta) []trace.Argument {
	args := []trace.Argument{ // Init empty args
		{ArgMeta: params[symbolIndex], Value: nil},
		{ArgMeta: params[trampIndex], Value: nil},
		{ArgMeta: params[callbackFuncIndex], Value: nil},
		{ArgMeta: params[callbackOffsetIndex], Value: nil},
		{ArgMeta: params[callbackOwnerIndex], Value: nil},
		{ArgMeta: params[flagsIndex], Value: nil},
		{ArgMeta: params[countIndex], Value: nil},
	}

	return args
}

// checkFtraceHooks checks for ftrace hooks
func checkFtraceHooks(eventsCounter counter.Counter, out chan *trace.Event, baseEvent *trace.Event, ftraceDef *Definition, selfLoadedProgs map[string]int) error {
	ftraceHooksBytes, err := getFtraceHooksData()
	if err != nil {
		return err
	}

	directArg := false // Direct arg flag

	for _, ftraceLine := range strings.Split(string(ftraceHooksBytes), "\n") {
		if len(ftraceLine) == 0 {
			continue
		}

		if directArg && strings.HasPrefix(ftraceLine, "\tdirect-->") {
			directArg = false // Turn off flag
			continue
		}

		ftraceLine = strings.ReplaceAll(ftraceLine, "\t", " ")

		params := ftraceDef.GetParams()
		args := initFtraceArgs(params)
		err = parseEventArgs(ftraceLine, args) // Fill args
		if err != nil {
			return err
		}

		if strings.Contains(args[flagsIndex].Value.(string), "D") {
			// On some kernels, a line follows after a hook with D (direct) parameter. Prepare to skip it.
			directArg = true // To be used in the next line (next iteration)
		}

		causedByTracee, newCount, err := isCausedBySelfLoadedProg(selfLoadedProgs, args[symbolIndex].Value.(string), args[countIndex].Value.(int))
		if err != nil {
			return err
		}

		if causedByTracee {
			continue
		}

		args[countIndex].Value = newCount
		symbol, ok := args[symbolIndex].Value.(string)
		if !ok {
			return errors.New("failed to cast symbol's value")
		}

		// Verify that we didn't report this symbol already, and it wasn't changed.
		// If we reported the symbol in the past, and now the count has reduced - report only if the callback was changed
		if existingEntry, found := reportedFtraceHooks.Get(symbol); found {
			if reflect.DeepEqual(existingEntry, args) ||
				(args[countIndex].Value.(int) < existingEntry[countIndex].Value.(int) &&
					args[callbackFuncIndex].Value == existingEntry[callbackFuncIndex].Value) {
				continue
			}
		}

		reportedFtraceHooks.Add(symbol, args) // Mark that we're reporting this hook, so we won't report it multiple times

		event := *baseEvent // shallow copy
		event.Timestamp = int(time.Now().UnixNano())
		event.Args = args
		event.ArgsNum = len(args)

		out <- &event
		_ = eventsCounter.Increment()
	}

	return nil
}

// isCausedBySelfLoadedProg checks if the hook is caused solely by tracee.
// Returns the effective count taking into consideration the hooks by tracee and ftrace based k[ret]probes
func isCausedBySelfLoadedProg(selfLoadedProgs map[string]int, symbol string, oldCount int) (bool, int, error) {
	newCount := oldCount

	numHooksFromTracee, found := selfLoadedProgs[symbol]
	if found { // Tracee uses this hook
		// In case of k[ret]probe, there might be multiple hooks on same symbol and the ftrace count will still be 1. Check kprobe list directly.
		numKprobes, err := numKprobesOnSymbol(symbol)
		if err != nil {
			return false, -1, err
		}

		if oldCount != 1 { // Someone else must be hooking using ftrace since tracee only causes 1 ftrace hook
			newCount = oldCount - 1 + (numKprobes - numHooksFromTracee) // Reduce count caused by tracee and add the number of k[ret]probes (other than tracee's)
		} else {
			if numKprobes == numHooksFromTracee { // count is 1 and all k[ret]probes are caused by us... there's nothing to report
				return true, -1, nil
			}
			newCount = numKprobes - numHooksFromTracee // The amount of k[ret]probes other than tracee's
		}
	}

	return false, newCount, nil
}

// parseEventArgs extract the event arguments from the ftrace line
func parseEventArgs(ftraceLine string, args []trace.Argument) error {
	ftraceParts := strings.Split(ftraceLine, " ")

	if len(ftraceParts) < 4 {
		return errors.New("ftrace: unexpected format of file... " + ftraceLine)
	}

	args[symbolIndex].Value = ftraceParts[0]

	count, err := strconv.Atoi(ftraceParts[1][1 : len(ftraceParts[1])-1]) // Remove parenthesis
	if err != nil {
		return err
	}
	args[countIndex].Value = count

	index := 2

	args[flagsIndex].Value = getFtraceFlags(ftraceParts, &index)

	var callback string
	args[trampIndex].Value, callback = fetchTrampAndCallback(ftraceParts, &index)
	args[callbackFuncIndex].Value, args[callbackOffsetIndex].Value, args[callbackOwnerIndex].Value = splitCallback(callback)

	return nil
}

type dupSymbolEntry struct {
	name     string
	hookType string
}

// numKprobesOnSymbol checks if there are multiple kprobes that are ftrace based on the ftrace symbol.
// The kprobe list file may have the following formats:
// c015d71a  k  vfs_read+0x0
// c015d71a  r  vfs_read+0x0 [FTRACE]
func numKprobesOnSymbol(ftracedSymbol string) (int, error) {
	data, err := readSysKernelFile("kprobes/list")
	if err != nil {
		return -1, err
	}

	numKprobesOnSymbol := 0

	// There may be multiple symbols in different addresses in the kernel.
	// When attaching a hook on such symbol, the kernel will attach multiple kprobes at those locations:
	// ffffffff9fd44d20  k  load_elf_phdrs+0x0    [FTRACE]
	// ffffffff9fd47b60  k  load_elf_phdrs+0x0    [FTRACE]
	// so we need to address this situation and not mark it as 2 or more different probes
	dupSymbolMap := map[dupSymbolEntry]string{}

	for _, kprobeLine := range strings.Split(string(data), "\n") {
		if len(kprobeLine) == 0 {
			continue
		}

		lineSplit := strings.Fields(kprobeLine)
		addr := lineSplit[0]
		hookType := lineSplit[1]

		// Verify the current kprobe is on our ftrace symbol
		kprobedSymbol := lineSplit[2][:strings.Index(lineSplit[2], "+")]
		if kprobedSymbol != ftracedSymbol {
			continue
		}

		// Verify this is an ftrace based kprobe
		if len(lineSplit) < 4 {
			continue // Not ftrace based as there is no [FTRACE] status
		}

		for _, status := range lineSplit[3:] {
			if status == "[FTRACE]" {
				key := dupSymbolEntry{
					name:     kprobedSymbol,
					hookType: hookType,
				}

				countedSymbolAddr, found := dupSymbolMap[key]
				if !found {
					// Not found - inc and add to map
					numKprobesOnSymbol++
					dupSymbolMap[key] = addr
				} else {
					// Same address - multiple hooks on same symbol - increment counter
					if addr == countedSymbolAddr {
						numKprobesOnSymbol++
					}
				}
				break
			}
		}
	}

	// Sanity check
	if numKprobesOnSymbol == 0 {
		logger.Debugw("Did not see our ftrace symbol in the kprobe list.. is ftrace based kprobe disabled? or the file is hooked")
	}

	return numKprobesOnSymbol, nil
}

// splitCallback splits it into separate parts
// callback can be of 3 forms:
// - some_func+0x0/0x10 [rootkit]
// - some_func+0x0/0x10
// - 0xffffffffc0637000
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

// getFtraceFlags extracts the flags
func getFtraceFlags(ftraceParts []string, index *int) string {
	flags := ""
	for ; *index < len(ftraceParts); *index++ {
		flag := strings.TrimSpace(ftraceParts[*index])
		if flag == "" {
			continue
		}

		if flag != "R" && flag != "I" && flag != "D" && flag != "O" && flag != "M" {
			// Assumes we've reached the end of flags section
			break
		}

		flags += flag
	}

	return flags
}
