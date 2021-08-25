package main

import (
	"bytes"
	_ "embed"

	"io/fs"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"plugin"
	"strings"

	"github.com/aquasecurity/tracee/tracee-rules/signatures/rego/regosig"
	"github.com/aquasecurity/tracee/tracee-rules/types"
)

//go:embed signatures/rego/helpers.rego
var regoHelpersCode string

func getSignatures(rulesDir string, rules []string) ([]types.Signature, error) {
	if rulesDir == "" {
		exePath, err := os.Executable()
		if err != nil {
			log.Printf("error getting executable path: %v", err)
		}
		rulesDir = filepath.Join(filepath.Dir(exePath), "rules")
	}
	gosigs, err := findGoSigs(rulesDir)
	if err != nil {
		return nil, err
	}
	opasigs, err := findRegoSigs(rulesDir)
	if err != nil {
		return nil, err
	}
	sigs := append(gosigs, opasigs...)
	var res []types.Signature
	if rules == nil {
		res = sigs
	} else {
		for _, s := range sigs {
			for _, r := range rules {
				if m, err := s.GetMetadata(); err == nil && m.ID == r {
					res = append(res, s)
				}
			}
		}
	}
	return res, nil
}

func findGoSigs(dir string) ([]types.Signature, error) {
	var res []types.Signature
	filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() || filepath.Ext(d.Name()) != ".so" {
			return nil
		}

		p, err := plugin.Open(path)
		if err != nil {
			log.Printf("error opening plugin %s: %v", path, err)
			return err
		}
		export, err := p.Lookup("ExportedSignatures")
		if err != nil {
			log.Printf("missing Export symbol in plugin %s", d.Name())
			return err
		}
		sigs := *export.(*[]types.Signature)
		res = append(res, sigs...)
		return nil
	})
	return res, nil
}

func findRegoSigs(dir string) ([]types.Signature, error) {
	regoHelpers := []string{regoHelpersCode}
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
			log.Printf("error reading file %s: %v", path, err)
			return nil
		}

		regoHelpers = append(regoHelpers, string(helperCode))
		return nil
	})

	var res []types.Signature
	filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() || !isRegoFile(d.Name()) || isHelper(d.Name()) {
			return nil
		}

		regoCode, err := ioutil.ReadFile(path)
		if err != nil {
			log.Printf("error reading file %s: %v", path, err)
			return nil
		}
		sig, err := regosig.NewRegoSignature(append(regoHelpers, string(regoCode))...)
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
			log.Printf("error creating rego signature with: %s: %v ", regoCode[0:newlineOffset], err)
			return nil
		}
		res = append(res, sig)
		return nil
	})
	return res, nil
}

func isRegoFile(name string) bool {
	return filepath.Ext(name) == ".rego"
}

func isHelper(name string) bool {
	return strings.HasSuffix(name, "helpers.rego")
}
