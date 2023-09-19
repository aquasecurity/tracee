package proctree

import (
	"bytes"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/olekukonko/tablewriter"
)

//
// Process Tree Output (might be used for debugging purposes). Provides a representation of the
// process tree close to the one provided by the "ps" command. A developer can use this as an
// example of how to obtain information and/or walk the "process tree".
//

// String returns a string representation of the process tree.
func (pt *ProcessTree) String() string {
	buffer := bytes.NewBufferString("")

	// getListOfChildrenPids returns a comma-separated list of children pids for a given process.
	getListOfChildrenPids := func(process *Process) string {
		var childrenPids []string
		for _, childHash := range process.GetChildren() { // for each child
			child, ok := pt.processes.Get(childHash)
			if !ok {
				continue
			}
			if !child.info.IsAlive() { // only running children
				continue
			}
			pid := fmt.Sprintf("%d", child.GetInfo().GetPid())
			childrenPids = append(childrenPids, pid)
		}
		// sort slice
		sort.Slice(childrenPids, func(i, j int) bool {
			one, _ := strconv.Atoi(childrenPids[i])
			two, _ := strconv.Atoi(childrenPids[j])
			return one < two
		})
		// join
		chdPids := strings.Join(childrenPids, ",")
		if len(chdPids) > 20 {
			chdPids = chdPids[:20] + "..."
		}
		return chdPids
	}

	// getListOfThreadsTids returns a comma-separated list of threads tids for a given process.
	getListOfThreadsTids := func(process *Process) string {
		var threadsTids []string
		for _, threadHash := range process.GetThreads() { // for each thread (if process is a thread group leader)
			thread, ok := pt.threads.Get(threadHash)
			if !ok {
				continue
			}
			if !thread.info.IsAlive() { // only running threads
				continue
			}
			tid := fmt.Sprintf("%d", thread.GetInfo().GetTid())
			threadsTids = append(threadsTids, tid)
		}
		// sort slice
		sort.Slice(threadsTids, func(i, j int) bool {
			one, _ := strconv.Atoi(threadsTids[i])
			two, _ := strconv.Atoi(threadsTids[j])
			return one < two
		})
		// join
		thrTids := strings.Join(threadsTids, ",")
		if len(thrTids) > 20 {
			thrTids = thrTids[:20] + "..."
		}
		return thrTids
	}

	// Use tablewriter to print the tree in a table
	newTable := func() *tablewriter.Table {
		table := tablewriter.NewWriter(buffer)
		table.SetHeader([]string{"Ppid", "Tid", "Pid", "EntityId", "Date", "Comm", "Children", "Threads"})
		// If debug() is enabled:
		// table.SetHeader([]string{"Ppid", "Tid", "Pid", "StartTime", "EntityId", "CMD", "Children", "Threads"})
		table.SetAutoWrapText(false)
		table.SetRowLine(false)
		table.SetAutoFormatHeaders(true)
		table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
		table.SetAlignment(tablewriter.ALIGN_LEFT)
		table.SetHeaderLine(true)
		table.SetBorder(true)
		return table
	}

	unsortedRows := [][]string{}

	// Walk the process tree and create a table row for each process:

	for _, hash := range pt.processes.Keys() { // for each process
		process, ok := pt.processes.Get(hash)
		if !ok {
			continue
		}
		if !process.info.IsAlive() {
			continue // only running processes
		}

		// create a row for the table
		processFeed := process.GetInfo().GetFeed()
		execName := processFeed.Name
		if len(execName) > 25 {
			execName = execName[:20] + "..."
		}
		// If debug() is enabled (and add hashString and start_time to unsortedRows)
		// hashStr := fmt.Sprintf("%v", process.GetHash())
		// start_time := process.GetInfo().GetStartTimeNS()
		tid := fmt.Sprintf("%v", processFeed.Tid)
		pid := fmt.Sprintf("%v", processFeed.Pid)
		ppid := fmt.Sprintf("%v", processFeed.PPid)
		date := process.GetInfo().GetStartTime().Format("2006-01-02 15:04:05")

		// add the row to the table
		unsortedRows = append(unsortedRows,
			[]string{
				ppid, tid, pid, date, execName,
				getListOfChildrenPids(process),
				getListOfThreadsTids(process),
			},
		)
	}

	// sort rows by pid, tid, ppid in this order
	sort.Slice(unsortedRows, func(i, j int) bool {
		one, _ := strconv.Atoi(unsortedRows[i][2])
		two, _ := strconv.Atoi(unsortedRows[j][2])
		if one == two {
			three, _ := strconv.Atoi(unsortedRows[i][1])
			four, _ := strconv.Atoi(unsortedRows[j][1])
			if three == four {
				five, _ := strconv.Atoi(unsortedRows[i][0])
				six, _ := strconv.Atoi(unsortedRows[j][0])
				return five < six
			}
			return three < four
		}
		return one < two
	})

	// print the table
	table := newTable()
	for _, row := range unsortedRows {
		table.Append(row)
	}
	table.Render()

	return buffer.String()
}
