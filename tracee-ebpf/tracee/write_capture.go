package tracee

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path"
	"strconv"
)

func (t *Tracee) processFileWrites() {
	type chunkMeta struct {
		BinType  binType
		MntID    uint32
		Metadata [24]byte
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
		Size  uint64
	}

	type bufferModuleMeta struct {
		Pid  uint32
		Size uint64
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

			pathname := path.Join(t.config.Capture.OutputPath, strconv.Itoa(int(meta.MntID)))
			if err := os.MkdirAll(pathname, 0755); err != nil {
				t.handleError(err)
				continue
			}
			filename := ""
			metaBuff := bytes.NewBuffer(meta.Metadata[:])
			var kernelModuleMeta kernelModuleMeta
			var bufferModuleMeta bufferModuleMeta
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
				if kernelModuleMeta.Pid == 0 {
					filename = fmt.Sprintf("module.dev-%d.inode-%d", kernelModuleMeta.DevID, kernelModuleMeta.Inode)
				} else {
					filename = fmt.Sprintf("module.dev-%d.inode-%d.pid-%d", kernelModuleMeta.DevID, kernelModuleMeta.Inode, kernelModuleMeta.Pid)
				}
			} else if meta.BinType == sendBufferModule {
				err = binary.Read(metaBuff, binary.LittleEndian, &bufferModuleMeta)
				if err != nil {
					t.handleError(err)
					continue
				}
				if bufferModuleMeta.Pid == 0 {
					filename = "module"
				} else {
					filename = fmt.Sprintf("module.pid-%d", bufferModuleMeta.Pid)
				}
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
			if meta.BinType == sendKernelModule || meta.BinType == sendBufferModule {
				var moduleSize uint64
				if meta.BinType == sendKernelModule {
					moduleSize = kernelModuleMeta.Size
				} else {
					moduleSize = bufferModuleMeta.Size
				}
				if uint64(meta.Size)+meta.Off == moduleSize {
					fileHash := getFileHash(fullname)
					os.Rename(fullname, fullname+"."+fileHash)
				}
			}
		case lost := <-t.lostWrChannel:
			t.stats.lostWrCounter.Increment(int(lost))
		}
	}
}
