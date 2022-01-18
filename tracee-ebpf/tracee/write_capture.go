package tracee

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
)

// binType is an enum that specifies the type of binary data sent in the file perf map
// binary types should match defined values in ebpf code
type binType uint8

const (
	sendVfsWrite binType = iota + 1
	sendMprotect
	sendKernelModule
	sendBpfObject
)

func (t *Tracee) processFileWrites() {
	type chunkMeta struct {
		BinType  binType
		CgroupID uint64
		Metadata [28]byte
		Size     int32
		Off      uint64
	}

	type vfsWriteMeta struct {
		DevID uint32
		Inode uint64
		Mode  uint32
		Pid   uint32
	}

	type kernelModuleMeta struct {
		DevID uint32
		Inode uint64
		Pid   uint32
		Size  uint32
	}

	type bpfObjectMeta struct {
		Name [16]byte
		Rand uint32
		Pid  uint32
		Size uint32
	}

	type mprotectWriteMeta struct {
		Ts uint64
	}

	const (
		S_IFMT uint32 = 0170000 // bit mask for the file type bit field

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
			dataBuff := bytes.NewBuffer(dataRaw)
			var meta chunkMeta
			appendFile := false
			err := binary.Read(dataBuff, binary.LittleEndian, &meta)
			if err != nil {
				t.handleError(err)
				continue
			}

			if meta.Size <= 0 {
				t.handleError(fmt.Errorf("error in file writer: invalid chunk size: %d", meta.Size))
				continue
			}
			if dataBuff.Len() < int(meta.Size) {
				t.handleError(fmt.Errorf("error in file writer: chunk too large: %d", meta.Size))
				continue
			}

			containerId := t.containers.GetCgroupInfo(meta.CgroupID).ContainerId
			if containerId == "" {
				containerId = "host"
			}
			pathname := path.Join(t.config.Capture.OutputPath, containerId)
			if err := os.MkdirAll(pathname, 0755); err != nil {
				t.handleError(err)
				continue
			}
			filename := ""
			metaBuff := bytes.NewBuffer(meta.Metadata[:])
			var kernelModuleMeta kernelModuleMeta
			var bpfObjectMeta bpfObjectMeta
			if meta.BinType == sendVfsWrite {
				var vfsMeta vfsWriteMeta
				err = binary.Read(metaBuff, binary.LittleEndian, &vfsMeta)
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
			} else if meta.BinType == sendMprotect {
				var mprotectMeta mprotectWriteMeta
				err = binary.Read(metaBuff, binary.LittleEndian, &mprotectMeta)
				if err != nil {
					t.handleError(err)
					continue
				}
				// note: size of buffer will determine maximum extracted file size! (as writes from kernel are immediate)
				filename = fmt.Sprintf("bin.%d", mprotectMeta.Ts)
			} else if meta.BinType == sendKernelModule {
				err = binary.Read(metaBuff, binary.LittleEndian, &kernelModuleMeta)
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
			} else if meta.BinType == sendBpfObject {
				err = binary.Read(metaBuff, binary.LittleEndian, &bpfObjectMeta)
				if err != nil {
					t.handleError(err)
					continue
				}
				bpfName := string(bytes.TrimRight(bpfObjectMeta.Name[:], "\x00"))
				filename = fmt.Sprintf("bpf.name-%s", bpfName)
				if bpfObjectMeta.Pid != 0 {
					filename = fmt.Sprintf("%s.pid-%d", filename, bpfObjectMeta.Pid)
				}
				filename = fmt.Sprintf("%s.%d", filename, bpfObjectMeta.Rand)
			} else {
				t.handleError(fmt.Errorf("error in file writer: unknown binary type: %d", meta.BinType))
				continue
			}

			fullname := path.Join(pathname, filename)

			f, err := os.OpenFile(fullname, os.O_CREATE|os.O_WRONLY, 0640)
			if err != nil {
				t.handleError(err)
				continue
			}
			if appendFile {
				if _, err := f.Seek(0, io.SeekEnd); err != nil {
					f.Close()
					t.handleError(err)
					continue
				}
			} else {
				if _, err := f.Seek(int64(meta.Off), io.SeekStart); err != nil {
					f.Close()
					t.handleError(err)
					continue
				}
			}

			dataBytes, err := readByteSliceFromBuff(dataBuff, int(meta.Size))
			if err != nil {
				f.Close()
				t.handleError(err)
				continue
			}
			if _, err := f.Write(dataBytes); err != nil {
				f.Close()
				t.handleError(err)
				continue
			}
			if err := f.Close(); err != nil {
				t.handleError(err)
				continue
			}
			// Rename the file to add hash when last chunk was received
			if meta.BinType == sendKernelModule || meta.BinType == sendBpfObject {
				switch meta.BinType {
				case sendKernelModule:
					if (uint32(meta.Size) + uint32(meta.Off)) == kernelModuleMeta.Size {
						fileHash, err := computeFileHash(fullname)
						if err != nil {
							t.handleError(err)
							continue
						}
						os.Rename(fullname, fullname+"."+fileHash)
					}
				case sendBpfObject:
					if (uint32(meta.Size) + uint32(meta.Off)) == bpfObjectMeta.Size {
						fileHash, err := computeFileHash(fullname)
						if err != nil {
							t.handleError(err)
							continue
						}
						// Delete the random int used to differentiate files
						dotIndex := strings.LastIndex(fullname, ".")
						os.Rename(fullname, fullname[:dotIndex]+"."+fileHash)
					}
				}
			}
		case lost := <-t.lostWrChannel:
			t.stats.lostWrCounter.Increment(int(lost))
		}
	}
}
