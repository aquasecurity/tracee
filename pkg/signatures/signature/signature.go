package signature

import (
	"bytes"
	"debug/elf"
	"io/fs"
	"os"
	"path/filepath"
	"plugin"
	"strings"

	embedded "github.com/aquasecurity/tracee"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/signatures/regosig"
	"github.com/aquasecurity/tracee/types/detect"
)

func Find(target string, partialEval bool, signaturesDir []string, signatures []string, aioEnabled bool) ([]detect.Signature, []detect.DataSource, error) {
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

		opasigs, err := findRegoSigs(target, partialEval, dir, aioEnabled)
		if err != nil {
			return nil, nil, err
		}
		sigs = append(sigs, opasigs...)
	}

	var res []detect.Signature
	if signatures == nil {
		res = sigs
	} else {
		res = findSigsOfSigs(sigs, signatures)
	}
	return res, datasources, nil
}

func findSigsOfSigs(loadedSigs []detect.Signature, chosenSigs []string) []detect.Signature {
	processedSigs := make(map[string]struct{}, len(chosenSigs))
	sigsOfsigs := make([]detect.Signature, 0, len(chosenSigs))

	// create a map for quick lookup of signatures by EventName or ID
	loadedSigMap := make(map[string]detect.Signature, len(loadedSigs))
	for _, sig := range loadedSigs {
		loadSigMeta, err := sig.GetMetadata()
		if err != nil {
			logger.Warnw("Failed to get signature metadata", "error", err)
			continue
		}
		loadedSigMap[loadSigMeta.EventName] = sig
		loadedSigMap[loadSigMeta.ID] = sig
	}

	// processSigsOfSig processes each signature recursively based on its selected signatures
	var processSigsOfSig func(sig detect.Signature)
	processSigsOfSig = func(sig detect.Signature) {
		sigMeta, err := sig.GetMetadata()
		if err != nil {
			logger.Warnw("Failed to get signature metadata", "error", err)
			return
		}

		// avoid re-processing the same signature
		if _, alreadyProcessed := processedSigs[sigMeta.EventName]; alreadyProcessed {
			return
		}
		processedSigs[sigMeta.EventName] = struct{}{}

		// add the current signature to the result list
		sigsOfsigs = append(sigsOfsigs, sig)

		// get selected signatures from this sig and process them
		selected := getSelectedSigsFromSig(loadedSigMap, sig)
		for sel := range selected {
			if selSig, ok := loadedSigMap[sel]; ok {
				processSigsOfSig(selSig) // recursively process the found signature
			}
		}
	}

	// start processing the chosen signatures
	for _, chosenName := range chosenSigs {
		if sig, ok := loadedSigMap[chosenName]; ok {
			processSigsOfSig(sig)
		}
	}

	return sigsOfsigs
}

func getSelectedSigsFromSig(loadedSigMap map[string]detect.Signature, sig detect.Signature) map[string]struct{} {
	selectedSigs := make(map[string]struct{})

	selectedEvents, err := sig.GetSelectedEvents()
	if err != nil {
		logger.Errorw("Failed to get selected events", "error", err)
		return selectedSigs
	}

	for _, sel := range selectedEvents {
		// ignore non-signature events
		if _, ok := events.Core.GetDefinitionIDByName(sel.Name); ok {
			continue
		}

		// only add if the signature is in the loadedSigMap
		if _, ok := loadedSigMap[sel.Name]; ok {
			selectedSigs[sel.Name] = struct{}{}
		} else {
			logger.Warnw("Selected signature not found", "signature", sel.Name)
		}
	}

	return selectedSigs
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

func findRegoSigs(target string, partialEval bool, dir string, aioEnabled bool) ([]detect.Signature, error) {
	var res []detect.Signature

	modules := make(map[string]string)
	modules["helper.rego"] = embedded.RegoHelpersCode

	regoHelpers := []string{embedded.RegoHelpersCode}

	errWD := filepath.WalkDir(dir,
		func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				logger.Errorw("Finding rego sigs", "error", err)
				return err
			}
			if d.IsDir() || d.Name() == "helpers.rego" {
				return nil
			}
			if !isHelper(d.Name()) {
				return nil
			}
			helperCode, err := os.ReadFile(path)
			if err != nil {
				logger.Errorw("Reading file " + path + ": " + err.Error())
				return nil
			}

			regoHelpers = append(regoHelpers, string(helperCode))
			modules[path] = string(helperCode)
			return nil
		},
	)
	if errWD != nil {
		logger.Errorw("Walking dir", "error", errWD)
	}

	errWD = filepath.WalkDir(dir,
		func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				logger.Errorw("Finding rego sigs", "error", err)
				return err
			}
			if d.IsDir() || !isRegoFile(d.Name()) || isHelper(d.Name()) {
				return nil
			}
			regoCode, err := os.ReadFile(path)
			if err != nil {
				logger.Errorw("Reading file " + path + ": " + err.Error())
				return nil
			}
			modules[path] = string(regoCode)
			if aioEnabled {
				return nil
			}
			sig, err := regosig.NewRegoSignature(target, partialEval, append(regoHelpers, string(regoCode))...)
			if err != nil {
				newlineOffset := bytes.Index(regoCode, []byte("\n"))
				if newlineOffset == -1 {
					codeLength := len(regoCode)
					if codeLength < 22 {
						newlineOffset = codeLength
					} else {
						newlineOffset = 22
					}
				}
				logger.Errorw("Creating rego signature with: " + string(regoCode[0:newlineOffset]) + ": " + err.Error())
				return nil
			}
			res = append(res, sig)
			return nil
		},
	)
	if errWD != nil {
		logger.Errorw("Walking dir", "error", errWD)
	}

	if aioEnabled {
		aio, err := regosig.NewAIO(
			modules,
			regosig.OPATarget(target),
			regosig.OPAPartial(partialEval),
		)
		if err != nil {
			return nil, err
		}
		return []detect.Signature{aio}, nil
	}

	return res, nil
}

func isRegoFile(name string) bool {
	return filepath.Ext(name) == ".rego"
}

func isHelper(name string) bool {
	return strings.HasSuffix(name, "helpers.rego")
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
