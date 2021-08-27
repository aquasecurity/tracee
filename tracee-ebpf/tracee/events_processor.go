package tracee

import (
	"fmt"
	"github.com/aquasecurity/tracee/tracee-ebpf/tracee/consts"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

func (t *Tracee) processLostEvents() {
	for {
		lost := <-t.lostEvChannel
		t.stats.lostEvCounter.Increment(int(lost))
	}
}

// shouldProcessEvent decides whether or not to drop an event before further processing it
func (t *Tracee) shouldProcessEvent(e RawEvent) bool {
	if t.config.Filter.RetFilter.Enabled {
		if filter, ok := t.config.Filter.RetFilter.Filters[e.Ctx.EventID]; ok {
			retVal := e.Ctx.Retval
			match := false
			for _, f := range filter.Equal {
				if retVal == f {
					match = true
					break
				}
			}
			if !match && len(filter.Equal) > 0 {
				return false
			}
			for _, f := range filter.NotEqual {
				if retVal == f {
					return false
				}
			}
			if (filter.Greater != consts.GreaterNotSetInt) && retVal <= filter.Greater {
				return false
			}
			if (filter.Less != consts.LessNotSetInt) && retVal >= filter.Less {
				return false
			}
		}
	}

	if t.config.Filter.ArgFilter.Enabled {
		for _, filter := range t.config.Filter.ArgFilter.Filters[e.Ctx.EventID] {
			argVal, ok := e.RawArgs[filter.argTag]
			if !ok {
				continue
			}
			// TODO: use type assertion instead of string convertion
			argValStr := fmt.Sprint(argVal)
			match := false
			for _, f := range filter.Equal {
				if argValStr == f || (f[len(f)-1] == '*' && strings.HasPrefix(argValStr, f[0:len(f)-1])) {
					match = true
					break
				}
			}
			if !match && len(filter.Equal) > 0 {
				return false
			}
			for _, f := range filter.NotEqual {
				if argValStr == f || (f[len(f)-1] == '*' && strings.HasPrefix(argValStr, f[0:len(f)-1])) {
					return false
				}
			}
		}
	}

	return true
}

func (t *Tracee) processEvent(ctx *context, args map[consts.ArgTag]interface{}) error {
	switch ctx.EventID {

	//capture written files
	case consts.VfsWriteEventID, consts.VfsWritevEventID:
		if t.config.Capture.FileWrite {
			filePath, ok := args[t.EncParamName[ctx.EventID%2]["pathname"]].(string)
			if !ok {
				return fmt.Errorf("error parsing vfs_write args")
			}
			// path should be absolute, except for e.g memfd_create files
			if filePath == "" || filePath[0] != '/' {
				return nil
			}
			dev, ok := args[t.EncParamName[ctx.EventID%2]["dev"]].(uint32)
			if !ok {
				return fmt.Errorf("error parsing vfs_write args")
			}
			inode, ok := args[t.EncParamName[ctx.EventID%2]["inode"]].(uint64)
			if !ok {
				return fmt.Errorf("error parsing vfs_write args")
			}

			// stop processing if write was already indexed
			fileName := fmt.Sprintf("%d/write.dev-%d.inode-%d", ctx.MntID, dev, inode)
			indexName, ok := t.writtenFiles[fileName]
			if ok && indexName == filePath {
				return nil
			}

			// index written file by original filepath
			t.writtenFiles[fileName] = filePath
		}

	case consts.SecurityBprmCheckEventID:

		//cache this pid by it's mnt ns
		if ctx.Pid == 1 {
			t.pidsInMntns.ForceAddBucketItem(ctx.MntID, ctx.HostPid)
		} else {
			t.pidsInMntns.AddBucketItem(ctx.MntID, ctx.HostPid)
		}

		//capture executed files
		if t.config.Capture.Exec {
			filePath, ok := args[t.EncParamName[ctx.EventID%2]["pathname"]].(string)
			if !ok {
				return fmt.Errorf("error parsing security_bprm_check args")
			}
			// path should be absolute, except for e.g memfd_create files
			if filePath == "" || filePath[0] != '/' {
				return nil
			}

			destinationDirPath := filepath.Join(t.config.Capture.OutputPath, strconv.Itoa(int(ctx.MntID)))
			if err := os.MkdirAll(destinationDirPath, 0755); err != nil {
				return err
			}
			destinationFilePath := filepath.Join(destinationDirPath, fmt.Sprintf("exec.%d.%s", ctx.Ts, filepath.Base(filePath)))

			var err error
			// try to access the root fs via another process in the same mount namespace (since the current process might have already died)
			pids := t.pidsInMntns.GetBucket(ctx.MntID)
			for _, pid := range pids { // will break on success
				err = nil
				sourceFilePath := fmt.Sprintf("/proc/%s/root%s", strconv.Itoa(int(pid)), filePath)
				var sourceFileStat os.FileInfo
				sourceFileStat, err = os.Stat(sourceFilePath)
				if err != nil {
					//TODO: remove dead pid from cache
					continue
				}

				sourceFileCtime := sourceFileStat.Sys().(*syscall.Stat_t).Ctim.Nano()
				capturedFileID := fmt.Sprintf("%d:%s", ctx.MntID, sourceFilePath)

				// create an in-memory profile
				if t.config.Capture.Profile {
					t.updateProfile(fmt.Sprintf("%s:%d", filepath.Join(destinationDirPath, fmt.Sprintf("exec.%s", filepath.Base(filePath))), sourceFileCtime), ctx.Ts)
				}

				//don't capture same file twice unless it was modified
				lastCtime, ok := t.capturedFiles[capturedFileID]
				if ok && lastCtime == sourceFileCtime {
					return nil
				}

				//capture
				err = CopyFileByPath(sourceFilePath, destinationFilePath)
				if err != nil {
					return err
				}
				//mark this file as captured
				t.capturedFiles[capturedFileID] = sourceFileCtime
				break
			}
			return err
		}
	}

	return nil
}

func (t *Tracee) updateProfile(sourceFilePath string, executionTs uint64) {
	if pf, ok := t.profiledFiles[sourceFilePath]; !ok {
		t.profiledFiles[sourceFilePath] = profilerInfo{
			Times:            1,
			FirstExecutionTs: executionTs,
		}
	} else {
		pf.Times = pf.Times + 1              // bump execution count
		t.profiledFiles[sourceFilePath] = pf // update
	}
}

// CopyFileByPath copies a file from src to dst
func CopyFileByPath(src, dst string) error {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return err
	}
	if !sourceFileStat.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", src)
	}
	source, err := os.Open(src)
	if err != nil {
		return err
	}
	defer source.Close()
	destination, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destination.Close()
	_, err = io.Copy(destination, source)
	if err != nil {
		return err
	}
	return nil
}
