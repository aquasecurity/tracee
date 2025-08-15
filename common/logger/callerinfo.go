package logger

import (
	"runtime"
	"strings"
)

type callerInfo struct {
	pkg       string
	file      string
	line      int
	functions []string
}

// getCallerInfo returns package, file and line from a function
// based on the given number of skips (stack frames).
func getCallerInfo(skip int) *callerInfo {
	var (
		pkg       string
		file      string
		line      int
		functions []string
	)

	// maximum depth of 20
	pcs := make([]uintptr, 20)
	n := runtime.Callers(skip+2, pcs)
	pcs = pcs[:n-1]

	frames := runtime.CallersFrames(pcs)
	firstCaller := true
	for {
		frame, more := frames.Next()
		if !more {
			break
		}

		fn := frame.Function
		fnStart := strings.LastIndexByte(fn, '/')
		if fnStart == -1 {
			fnStart = 0
		} else {
			fnStart++
		}

		fn = fn[fnStart:]
		pkgEnd := strings.IndexByte(fn, '.')
		if pkgEnd == -1 {
			fnStart = 0
		} else {
			fnStart = pkgEnd + 1
		}
		functions = append(functions, fn[fnStart:])

		if firstCaller {
			line = frame.Line
			file = frame.File
			// set file as relative path
			pat := "tracee/"
			traceeIndex := strings.Index(file, pat)
			if traceeIndex != -1 {
				file = file[traceeIndex+len(pat):]
			}
			pkg = fn[:pkgEnd]

			firstCaller = false
		}
	}

	return &callerInfo{
		pkg:       pkg,
		file:      file,
		line:      line,
		functions: functions,
	}
}
