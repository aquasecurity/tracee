package signature

import (
	"debug/elf"
	"io/fs"
	"os"
	"path/filepath"
	"plugin"
	"strings"

	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/types/detect"
)

func Find(signaturesDir []string, signatures []string) ([]detect.Signature, []detect.DataSource, error) {
	if len(signaturesDir) == 0 {
		exePath, err := os.Executable()
		if err != nil {
			logger.Errorw("Getting executable path: " + err.Error())
		}
		signaturesDir = []string{filepath.Join(filepath.Dir(exePath), "signatures")}
	}
	var sigs []detect.Signature
	var datasources []detect.DataSource

	for _, dir := range signaturesDir {
		if strings.TrimSpace(dir) == "" {
			continue
		}

		gosigs, ds, err := findGoSigs(dir)
		if err != nil {
			return nil, nil, err
		}

		sigs = append(sigs, gosigs...)
		datasources = append(datasources, ds...)
	}

	var res []detect.Signature
	if signatures == nil {
		res = sigs
	} else {
		for _, s := range sigs {
			for _, r := range signatures {
				if m, err := s.GetMetadata(); err == nil &&
					(m.ID == r || m.EventName == r) {
					res = append(res, s)
				}
			}
		}
	}
	return res, datasources, nil
}

func findGoSigs(dir string) ([]detect.Signature, []detect.DataSource, error) {
	var signatures []detect.Signature
	var datasources []detect.DataSource

	if isBinaryStatic() {
		logger.Warnw("The tracee static can't load golang signatures. Skipping ...")
		return signatures, datasources, nil
	}

	errWD := filepath.WalkDir(dir,
		func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				logger.Errorw("Finding golang sigs", "error", err)
				return err
			}

			if d.IsDir() || filepath.Ext(d.Name()) != ".so" {
				return nil
			}

			p, err := plugin.Open(path)
			if err != nil {
				logger.Errorw("Opening plugin " + path + ": " + err.Error())
				return err
			}
			exportSigs, err := p.Lookup("ExportedSignatures")
			if err != nil {
				logger.Errorw("Missing Export symbol in plugin " + d.Name())
				return err
			}
			sigs := *exportSigs.(*[]detect.Signature)

			exportDS, err := p.Lookup("ExportedDataSources")
			if err != nil {
				logger.Debugw("No ExportedDataSources symbol in plugin " + d.Name())
				// we don't return here because some plugins might not have datasources
			}

			var ds []detect.DataSource
			if exportDS != nil {
				ds = *exportDS.(*[]detect.DataSource)
			}

			signatures = append(signatures, sigs...)
			datasources = append(datasources, ds...)
			return nil
		},
	)
	if errWD != nil {
		logger.Errorw("Walking dir", "error", errWD)
	}

	return signatures, datasources, nil
}

func isBinaryStatic() bool {
	exePath, err := os.Executable()
	if err != nil {
		logger.Errorw("Error getting tracee executable path", "error", err)
		return false
	}

	loadedObject, err := elf.Open(exePath)
	if err != nil {
		logger.Errorw("Error opening tracee executable", "error", err)
		return false
	}

	defer func() {
		if err = loadedObject.Close(); err != nil {
			logger.Errorw("Error closing file", "error", err)
		}
	}()

	_, err = loadedObject.DynamicSymbols()

	return err != nil
}
