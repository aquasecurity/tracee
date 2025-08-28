package ebpf

import (
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/aquasecurity/tracee/common"
	"github.com/aquasecurity/tracee/common/errfmt"
	"github.com/aquasecurity/tracee/common/logger"
	"github.com/aquasecurity/tracee/common/timeutil"
	"github.com/aquasecurity/tracee/pkg/bufferdecoder"
)

func (t *Tracee) handleFileCaptures(ctx context.Context) {
	logger.Debugw("Starting handleFileCaptures go routine")
	defer logger.Debugw("Stopped handleFileCaptures go routine")

	const (
		// stat_S_IFMT uint32 = 0170000 // bit mask for the file type bit field
		_S_IFSOCK uint32 = 0140000 // socket
		_S_IFLNK  uint32 = 0120000 // symbolic link
		_S_IFREG  uint32 = 0100000 // regular file
		_S_IFBLK  uint32 = 0060000 // block device
		_S_IFDIR  uint32 = 0040000 // directory
		_S_IFCHR  uint32 = 0020000 // character device
		_S_IFIFO  uint32 = 0010000 // FIFO
	)

	for {
		select {
		case dataRaw := <-t.fileCapturesChannel:
			if len(dataRaw) == 0 {
				continue
			}
			ebpfMsgDecoder := bufferdecoder.New(dataRaw, t.dataTypeDecoder)
			var meta bufferdecoder.ChunkMeta
			appendFile := false

			err := ebpfMsgDecoder.DecodeChunkMeta(&meta)
			if err != nil {
				t.handleError(err)
				continue
			}

			if meta.Size <= 0 {
				t.handleError(errfmt.Errorf("invalid chunk size: %d", meta.Size))
				continue
			}

			if ebpfMsgDecoder.BuffLen() < int(meta.Size) {
				t.handleError(errfmt.Errorf("chunk too large: %d", meta.Size))
				continue
			}

			cgroup, _ := t.containers.GetCgroupInfo(meta.CgroupID)

			containerId := cgroup.ContainerId
			if containerId == "" {
				containerId = "host"
			}
			pathname := containerId
			if err := common.MkdirAtExist(t.OutDir, pathname, 0755); err != nil {
				t.handleError(err)
				continue
			}
			filename := ""
			metaBuffDecoder := bufferdecoder.New(meta.Metadata[:], t.dataTypeDecoder)
			var kernelModuleMeta bufferdecoder.KernelModuleMeta
			var bpfObjectMeta bufferdecoder.BpfObjectMeta
			if meta.BinType == bufferdecoder.SendVfsWrite || meta.BinType == bufferdecoder.SendVfsRead {
				var vfsMeta bufferdecoder.VfsFileMeta
				err = metaBuffDecoder.DecodeVfsFileMeta(&vfsMeta)
				if err != nil {
					t.handleError(err)
					continue
				}
				if vfsMeta.Mode&_S_IFSOCK == _S_IFSOCK || vfsMeta.Mode&_S_IFCHR == _S_IFCHR || vfsMeta.Mode&_S_IFIFO == _S_IFIFO {
					appendFile = true
				}
				var operation string
				if meta.BinType == bufferdecoder.SendVfsRead {
					operation = "read"
				} else {
					operation = "write"
				}
				if vfsMeta.Pid == 0 {
					filename = fmt.Sprintf(
						"%s.dev-%d.inode-%d",
						operation,
						vfsMeta.DevID,
						vfsMeta.Inode,
					)
				} else { // Only applies for write to /dev/null
					filename = fmt.Sprintf(
						"%s.dev-%d.inode-%d.pid-%d",
						operation,
						vfsMeta.DevID,
						vfsMeta.Inode,
						vfsMeta.Pid,
					)
				}
			} else if meta.BinType == bufferdecoder.SendMprotect {
				var mprotectMeta bufferdecoder.MprotectWriteMeta
				err = metaBuffDecoder.DecodeMprotectWriteMeta(&mprotectMeta)
				if err != nil {
					t.handleError(err)
					continue
				}
				// note: size of buffer will determine maximum extracted file size! (as writes from kernel are immediate)
				mprotectMeta.Ts = timeutil.BootToEpochNS(uint64(mprotectMeta.Ts))
				filename = fmt.Sprintf("bin.pid-%d.ts-%d", mprotectMeta.Pid, mprotectMeta.Ts)
			} else if meta.BinType == bufferdecoder.SendKernelModule {
				err = metaBuffDecoder.DecodeKernelModuleMeta(&kernelModuleMeta)
				if err != nil {
					t.handleError(err)
					continue
				}
				filename = "module"
				if kernelModuleMeta.DevID != 0 {
					filename = fmt.Sprintf("%s.dev-%d", filename, kernelModuleMeta.DevID)
				}
				if kernelModuleMeta.Inode != 0 {
					filename = fmt.Sprintf("%s.inode-%d", filename, kernelModuleMeta.Inode)
				}
				if kernelModuleMeta.Pid != 0 {
					filename = fmt.Sprintf("%s.pid-%d", filename, kernelModuleMeta.Pid)
				}
			} else if meta.BinType == bufferdecoder.SendBpfObject {
				err = metaBuffDecoder.DecodeBpfObjectMeta(&bpfObjectMeta)
				if err != nil {
					t.handleError(err)
					continue
				}
				bpfName := common.TrimTrailingNUL(bpfObjectMeta.Name[:])
				filename = fmt.Sprintf("bpf.name-%s", bpfName)
				if bpfObjectMeta.Pid != 0 {
					filename = fmt.Sprintf("%s.pid-%d", filename, bpfObjectMeta.Pid)
				}
				filename = fmt.Sprintf("%s.%d", filename, bpfObjectMeta.Rand)
			} else {
				t.handleError(errfmt.Errorf("unknown binary type: %d", meta.BinType))
				continue
			}

			fullname := path.Join(pathname, filename)

			f, err := common.OpenAt(t.OutDir, fullname, os.O_CREATE|os.O_WRONLY, 0640)
			if err != nil {
				t.handleError(err)
				continue
			}
			if appendFile {
				if _, err := f.Seek(0, io.SeekEnd); err != nil {
					if err := f.Close(); err != nil {
						t.handleError(err)
					}
					t.handleError(err)
					continue
				}
			} else {
				if _, err := f.Seek(int64(meta.Off), io.SeekStart); err != nil {
					if err := f.Close(); err != nil {
						t.handleError(err)
					}
					t.handleError(err)
					continue
				}
			}

			dataBytes, err := ebpfMsgDecoder.ReadBytesLen(int(meta.Size))
			if err != nil {
				if err := f.Close(); err != nil {
					t.handleError(err)
				}
				t.handleError(err)
				continue
			}
			if _, err := f.Write(dataBytes); err != nil {
				if err := f.Close(); err != nil {
					t.handleError(err)
				}
				t.handleError(err)
				continue
			}
			if err := f.Close(); err != nil {
				t.handleError(err)
				continue
			}
			// Rename the file to add hash when last chunk was received
			if meta.BinType == bufferdecoder.SendKernelModule && uint32(meta.Size)+uint32(meta.Off) == kernelModuleMeta.Size {
				fileHash, _ := t.computeOutFileHash(fullname)
				err := common.RenameAt(t.OutDir, fullname, t.OutDir, fullname+"."+fileHash)
				if err != nil {
					t.handleError(err)
					continue
				}
			} else if meta.BinType == bufferdecoder.SendBpfObject && (uint32(meta.Size)+uint32(meta.Off)) == bpfObjectMeta.Size {
				fileHash, _ := t.computeOutFileHash(fullname)
				// Delete the random int used to differentiate files
				dotIndex := strings.LastIndex(fullname, ".")
				err := common.RenameAt(t.OutDir, fullname, t.OutDir, fullname[:dotIndex]+"."+fileHash)
				if err != nil {
					t.handleError(err)
					continue
				}
			}

		case lost := <-t.lostCapturesChannel:
			if err := t.stats.LostWrCount.Increment(lost); err != nil {
				logger.Errorw("Incrementing lost capture count", "error", err)
			}
			logger.Warnw(fmt.Sprintf("Lost %d capture events", lost))

		case <-ctx.Done():
			return
		}
	}
}
