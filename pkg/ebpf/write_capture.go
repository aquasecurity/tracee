package ebpf

import (
	"fmt"
	"io"
	"os"
	"path"

	"github.com/aquasecurity/tracee/pkg/bufferdecoder"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/utils"
)

func (t *Tracee) processFileWrites() {

	const (
		//S_IFMT uint32 = 0170000 // bit mask for the file type bit field
		S_IFSOCK uint32 = 0140000 // socket
		S_IFLNK  uint32 = 0120000 // symbolic link
		S_IFREG  uint32 = 0100000 // regular file
		S_IFBLK  uint32 = 0060000 // block device
		S_IFDIR  uint32 = 0040000 // directory
		S_IFCHR  uint32 = 0020000 // character device
		S_IFIFO  uint32 = 0010000 // FIFO
	)

	for {
		select {
		case dataRaw := <-t.fileWrChannel:
			if len(dataRaw) == 0 {
				continue
			}
			ebpfMsgDecoder := bufferdecoder.New(dataRaw)
			var meta bufferdecoder.ChunkMeta
			appendFile := false

			err := ebpfMsgDecoder.DecodeChunkMeta(&meta)
			if err != nil {
				t.handleError(err)
				continue
			}

			if meta.Size <= 0 {
				t.handleError(fmt.Errorf("error in file writer: invalid chunk size: %d", meta.Size))
				continue
			}

			if ebpfMsgDecoder.BuffLen() < int(meta.Size) {
				t.handleError(fmt.Errorf("error in file writer: chunk too large: %d", meta.Size))
				continue
			}

			containerId := t.containers.GetCgroupInfo(meta.CgroupID).Container.ContainerId
			if containerId == "" {
				containerId = "host"
			}
			pathname := containerId
			if err := utils.MkdirAtExist(t.outDir, pathname, 0755); err != nil {
				t.handleError(err)
				continue
			}
			filename := ""
			metaBuffDecoder := bufferdecoder.New(meta.Metadata[:])
			var kernelModuleMeta bufferdecoder.KernelModuleMeta
			if meta.BinType == bufferdecoder.SendVfsWrite {
				var vfsMeta bufferdecoder.VfsWriteMeta
				err = metaBuffDecoder.DecodeVfsWriteMeta(&vfsMeta)
				if err != nil {
					t.handleError(err)
					continue
				}
				if vfsMeta.Mode&S_IFSOCK == S_IFSOCK || vfsMeta.Mode&S_IFCHR == S_IFCHR || vfsMeta.Mode&S_IFIFO == S_IFIFO {
					appendFile = true
				}
				if vfsMeta.Pid == 0 {
					filename = fmt.Sprintf("write.dev-%d.inode-%d", vfsMeta.DevID, vfsMeta.Inode)
				} else {
					filename = fmt.Sprintf("write.dev-%d.inode-%d.pid-%d", vfsMeta.DevID, vfsMeta.Inode, vfsMeta.Pid)
				}
			} else if meta.BinType == bufferdecoder.SendMprotect {
				var mprotectMeta bufferdecoder.MprotectWriteMeta
				err = metaBuffDecoder.DecodeMprotectWriteMeta(&mprotectMeta)
				if err != nil {
					t.handleError(err)
					continue
				}
				// note: size of buffer will determine maximum extracted file size! (as writes from kernel are immediate)
				filename = fmt.Sprintf("bin.%d", mprotectMeta.Ts)
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
			} else {
				t.handleError(fmt.Errorf("error in file writer: unknown binary type: %d", meta.BinType))
				continue
			}

			fullname := path.Join(pathname, filename)

			f, err := utils.OpenAt(t.outDir, fullname, os.O_CREATE|os.O_WRONLY, 0640)
			if err != nil {
				t.handleError(err)
				continue
			}
			if appendFile {
				if _, err := f.Seek(0, io.SeekEnd); err != nil {
					t.handleError(err)
					err = f.Close()
					if err != nil {
						t.handleError(err)
					}
					continue
				}
			} else {
				if _, err := f.Seek(int64(meta.Off), io.SeekStart); err != nil {
					t.handleError(err)
					err = f.Close()
					if err != nil {
						t.handleError(err)
					}
					continue
				}
			}

			dataBytes, err := bufferdecoder.ReadByteSliceFromBuff(ebpfMsgDecoder, int(meta.Size))
			if err != nil {
				t.handleError(err)
				err = f.Close()
				if err != nil {
					t.handleError(err)
				}
				continue
			}
			if _, err := f.Write(dataBytes); err != nil {
				t.handleError(err)
				err = f.Close()
				if err != nil {
					t.handleError(err)
				}
				continue
			}
			if err := f.Close(); err != nil {
				t.handleError(err)
				continue
			}
			// Rename the file to add hash when last chunk was received
			if meta.BinType == bufferdecoder.SendKernelModule {
				if uint64(meta.Size)+meta.Off == kernelModuleMeta.Size {
					fileHash, _ := t.computeOutFileHash(fullname)
					err := utils.RenameAt(t.outDir, fullname, t.outDir, fullname+"."+fileHash)
					if err != nil {
						t.handleError(err)
					}
				}
			}
		case lost := <-t.lostWrChannel:
			// When terminating tracee-ebpf the lost channel receives multiple "0 lost events" events.
			// This check prevents those 0 lost events messages to be written to stderr until the bug is fixed:
			// https://github.com/aquasecurity/libbpfgo/issues/122
			if lost > 0 {
				err := t.stats.LostWrCount.Increment(lost)
				if err != nil {
					logger.Error("Incrementing lost write count", "error", err)
				}
				logger.Warn(fmt.Sprintf("Lost %d write events", lost))
			}
		}
	}
}
