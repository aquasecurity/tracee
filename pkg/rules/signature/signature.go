package signature

import (
	_ "embed"

	"bytes"
	"fmt"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
	"plugin"
	"strings"

	"github.com/aquasecurity/tracee/pkg/logger"

	embedded "github.com/aquasecurity/tracee"
	"github.com/aquasecurity/tracee/pkg/rules/celsig"
	"github.com/aquasecurity/tracee/pkg/rules/regosig"
	"github.com/aquasecurity/tracee/types/detect"
)

func Find(target string, partialEval bool, rulesDir string, rules []string, aioEnabled bool) ([]detect.Signature, error) {
	if rulesDir == "" {
		exePath, err := os.Executable()
		if err != nil {
			logger.Error("getting executable path: " + err.Error())
		}
		rulesDir = filepath.Join(filepath.Dir(exePath), "rules")
	}
	gosigs, err := findGoSigs(rulesDir)
	if err != nil {
		return nil, err
	}
	opasigs, err := findRegoSigs(target, partialEval, rulesDir, aioEnabled)
	if err != nil {
		return nil, err
	}
	sigs := append(gosigs, opasigs...)
	celsigs, err := celsig.NewSignaturesFromDir(rulesDir)
	if err != nil {
		return nil, fmt.Errorf("failed loading CEL signatures: %w", err)
	}
	sigs = append(sigs, celsigs...)

	var res []detect.Signature
	if rules == nil {
		res = sigs
	} else {
		for _, s := range sigs {
			for _, r := range rules {
				if m, err := s.GetMetadata(); err == nil &&
					(m.ID == r || m.EventName == r) {
					res = append(res, s)
				}
			}
		}
	}
	return res, nil
}

func findGoSigs(dir string) ([]detect.Signature, error) {
	var res []detect.Signature
	filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() || filepath.Ext(d.Name()) != ".so" {
			return nil
		}

		p, err := plugin.Open(path)
		if err != nil {
			logger.Error("opening plugin " + path + ": " + err.Error())
			return err
		}
		export, err := p.Lookup("ExportedSignatures")
		if err != nil {
			logger.Error("missing Export symbol in plugin " + d.Name())
			return err
		}
		sigs := *export.(*[]detect.Signature)
		res = append(res, sigs...)
		return nil
	})
	return res, nil
}

func findRegoSigs(target string, partialEval bool, dir string, aioEnabled bool) ([]detect.Signature, error) {
	modules := make(map[string]string)
	modules["helper.rego"] = embedded.RegoHelpersCode

	regoHelpers := []string{embedded.RegoHelpersCode}
	filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() || d.Name() == "helpers.rego" {
			return nil
		}

		if !isHelper(d.Name()) {
			return nil
		}

		helperCode, err := ioutil.ReadFile(path)
		if err != nil {
			logger.Error("reading file " + path + ": " + err.Error())
			return nil
		}

		regoHelpers = append(regoHelpers, string(helperCode))
		modules[path] = string(helperCode)
		return nil
	})

	var res []detect.Signature
	filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() || !isRegoFile(d.Name()) || isHelper(d.Name()) {
			return nil
		}

		regoCode, err := ioutil.ReadFile(path)
		if err != nil {
			logger.Error("reading file " + path + ": " + err.Error())
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
			logger.Error("creating rego signature with: " + string(regoCode[0:newlineOffset]) + ": " + err.Error())
			return nil
		}
		res = append(res, sig)
		return nil
	})
	if aioEnabled {
		aio, err := regosig.NewAIO(modules,
			regosig.OPATarget(target),
			regosig.OPAPartial(partialEval))
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
