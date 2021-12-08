package tracee

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/aquasecurity/tracee/pkg/external"
)

func (t *Tracee) processLostEvents() {
	for {
		lost := <-t.lostEvChannel
		t.stats.lostEvCounter.Increment(int(lost))
	}
}

// shouldProcessEvent decides whether or not to drop an event before further processing it
func (t *Tracee) shouldProcessEvent(ctx *context, args map[string]interface{}) bool {
	if t.config.Filter.RetFilter.Enabled {
		if filter, ok := t.config.Filter.RetFilter.Filters[ctx.EventID]; ok {
			retVal := ctx.Retval
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
			if (filter.Greater != GreaterNotSetInt) && retVal <= filter.Greater {
				return false
			}
			if (filter.Less != LessNotSetInt) && retVal >= filter.Less {
				return false
			}
		}
	}

	if t.config.Filter.ArgFilter.Enabled {
		for argName, filter := range t.config.Filter.ArgFilter.Filters[ctx.EventID] {
			argVal, ok := args[argName]
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

func (t *Tracee) processEvent(ctx *context, args map[string]interface{}, argMetas *[]external.ArgMeta) error {
	switch ctx.EventID {

	//capture written files
	case VfsWriteEventID, VfsWritevEventID:
		if t.config.Capture.FileWrite {
			filePath, ok := args["pathname"].(string)
			if !ok {
				return fmt.Errorf("error parsing vfs_write args")
			}
			// path should be absolute, except for e.g memfd_create files
			if filePath == "" || filePath[0] != '/' {
				return nil
			}
			dev, ok := args["dev"].(uint32)
			if !ok {
				return fmt.Errorf("error parsing vfs_write args")
			}
			inode, ok := args["inode"].(uint64)
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

	case SchedProcessExecEventID:

		//cache this pid by it's mnt ns
		if ctx.Pid == 1 {
			t.pidsInMntns.ForceAddBucketItem(ctx.MntID, ctx.HostPid)
		} else {
			t.pidsInMntns.AddBucketItem(ctx.MntID, ctx.HostPid)
		}

		//capture executed files
		if t.config.Capture.Exec || t.config.Output.ExecHash {
			filePath, ok := args["pathname"].(string)
			if !ok {
				return fmt.Errorf("error parsing sched_process_exec args")
			}
			// path should be absolute, except for e.g memfd_create files
			if filePath == "" || filePath[0] != '/' {
				return nil
			}

			var err error
			// try to access the root fs via another process in the same mount namespace (since the current process might have already died)
			pids := t.pidsInMntns.GetBucket(ctx.MntID)
			for _, pid := range pids { // will break on success
				err = nil
				sourceFilePath := fmt.Sprintf("/proc/%s/root%s", strconv.Itoa(int(pid)), filePath)
				sourceFileCtime, ok := args["ctime"].(uint64)
				if !ok {
					return fmt.Errorf("error parsing sched_process_exec args: ctime")
				}
				castedSourceFileCtime := int64(sourceFileCtime)

				capturedFileID := fmt.Sprintf("%d:%s", ctx.MntID, sourceFilePath)
				if t.config.Capture.Exec {
					destinationDirPath := filepath.Join(t.config.Capture.OutputPath, strconv.Itoa(int(ctx.MntID)))
					if err := os.MkdirAll(destinationDirPath, 0755); err != nil {
						return err
					}
					destinationFilePath := filepath.Join(destinationDirPath, fmt.Sprintf("exec.%d.%s", ctx.Ts, filepath.Base(filePath)))

					// create an in-memory profile
					if t.config.Capture.Profile {
						t.updateProfile(fmt.Sprintf("%s:%d", filepath.Join(destinationDirPath, fmt.Sprintf("exec.%s", filepath.Base(filePath))), castedSourceFileCtime), ctx.Ts)
					}

					//don't capture same file twice unless it was modified
					lastCtime, ok := t.capturedFiles[capturedFileID]
					if !ok || lastCtime != castedSourceFileCtime {
						//capture
						err = CopyFileByPath(sourceFilePath, destinationFilePath)
						if err != nil {
							return err
						}
						//mark this file as captured
						t.capturedFiles[capturedFileID] = castedSourceFileCtime
					}
				}

				if t.config.Output.ExecHash {
					var hashInfoObj fileExecInfo
					var currentHash string
					hashInfoInterface, ok := t.fileHashes.Get(capturedFileID)

					// cast to fileExecInfo
					if ok {
						hashInfoObj = hashInfoInterface.(fileExecInfo)
					}
					// Check if cache can be used
					if ok && hashInfoObj.LastCtime == castedSourceFileCtime {
						currentHash = hashInfoObj.Hash
					} else {
						currentHash = getFileHash(sourceFilePath)
						hashInfoObj = fileExecInfo{castedSourceFileCtime, currentHash}
						t.fileHashes.Add(capturedFileID, hashInfoObj)
					}

					hashMeta := external.ArgMeta{"sha256", "const char*"}
					*argMetas = append(*argMetas, hashMeta)
					ctx.Argnum += 1
					args["sha256"] = currentHash
				}

				break
			}
			return err
		}

	case CgroupMkdirEventID:
		cgroupId, ok := args["cgroup_id"].(uint64)
		if !ok {
			return fmt.Errorf("error parsing cgroup_mkdir args")
		}
		path, ok := args["cgroup_path"].(string)
		if !ok {
			return fmt.Errorf("error parsing cgroup_mkdir args")
		}
		info, err := t.containers.CgroupUpdate(cgroupId, path)
		if err == nil && info.ContainerId == "" {
			// If not a new container (no regex match) - remove from the bpf container_map
			t.containers.RemoveFromBpfMap(t.bpfModule, cgroupId)
		}

	case CgroupRmdirEventID:
		cgroupId, ok := args["cgroup_id"].(uint64)
		if !ok {
			return fmt.Errorf("error parsing cgroup_rmdir args")
		}
		t.containers.CgroupRemove(cgroupId)
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
