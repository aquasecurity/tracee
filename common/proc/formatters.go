package proc

import "strconv"

// GetTaskPath returns the path to the task directory of a process given its PID.
// The path is in the form /proc/<pid>/task.
func GetTaskPath(pid int32) string {
	pidStr := strconv.FormatInt(int64(pid), 10)
	return "/proc/" + pidStr + "/task"
}

// GetStatPath returns the path to the stat file of a process given its PID.
// The path is in the form /proc/<pid>/stat.
func GetStatPath(pid int32) string {
	pidStr := strconv.FormatInt(int64(pid), 10)
	return "/proc/" + pidStr + "/stat"
}

// GetStatusPath returns the path to the status file of a process given its PID.
// The path is in the form /proc/<pid>/status.
func GetStatusPath(pid int32) string {
	pidStr := strconv.FormatInt(int64(pid), 10)
	return "/proc/" + pidStr + "/status"
}

// GetTaskStatPath returns the path to the stat file of a thread given its PID and TID.
// The path is in the form /proc/<pid>/task/<tid>/stat.
func GetTaskStatPath(pid, tid int32) string {
	pidStr := strconv.FormatInt(int64(pid), 10)
	tidStr := strconv.FormatInt(int64(tid), 10)
	return "/proc/" + pidStr + "/task/" + tidStr + "/stat"
}

// GetTaskStatusPath returns the path to the status file of a thread given its PID and TID.
// The path is in the form /proc/<pid>/task/<tid>/status.
func GetTaskStatusPath(pid, tid int32) string {
	pidStr := strconv.FormatInt(int64(pid), 10)
	tidStr := strconv.FormatInt(int64(tid), 10)
	return "/proc/" + pidStr + "/task/" + tidStr + "/status"
}

// GetProcExePath returns the path to the executable of a process given its PID.
// The path is in the form /proc/<pid>/exe.
func GetProcExePath(pid int32) string {
	pidStr := strconv.FormatInt(int64(pid), 10)
	return "/proc/" + pidStr + "/exe"
}

// GetProcNSDirPath returns the path to the directory containing the namespaces of a process given its PID.
// The path is in the form /proc/<pid>/ns.
func GetProcNSDirPath(pid int32) string {
	pidStr := strconv.FormatInt(int64(pid), 10)
	return "/proc/" + pidStr + "/ns"
}

// GetProcNSPath returns the path to a specific namespace of a process given its PID and the namespace name.
// The path is in the form /proc/<pid>/ns/<nsName>.
func GetProcNSPath(pid int32, nsName string) string {
	return GetProcNSDirPath(pid) + "/" + nsName
}
