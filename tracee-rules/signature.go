package main

import (
	"bytes"
	_ "embed"

	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"plugin"
	"strings"

	"github.com/aquasecurity/tracee/tracee-rules/signatures/rego/regosig"
	"github.com/aquasecurity/tracee/tracee-rules/types"
)

//go:embed signatures/helpers/helpers.rego
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
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("error reading plugins directory %s: %v", dir, err)
	}
	var res []types.Signature
	for _, file := range files {
		if filepath.Ext(file.Name()) != ".so" {
			continue
		}
		p, err := plugin.Open(filepath.Join(dir, file.Name()))
		if err != nil {
			log.Printf("error opening plugin %s: %v", file.Name(), err)
			continue
		}
		export, err := p.Lookup("ExportedSignatures")
		if err != nil {
			log.Printf("missing Export symbol in plugin %s", file.Name())
			continue
		}
		sigs := *export.(*[]types.Signature)
		res = append(res, sigs...)
	}
	return res, nil
}

func findRegoSigs(dir string) ([]types.Signature, error) {
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("error reading plugins directory %s: %v", dir, err)
	}

	var res []types.Signature

	regoHelpers := []string{regoHelpersCode}
	for _, file := range files {
		if !isHelper(file.Name()) {
			continue
		}

		helperCode, err := ioutil.ReadFile(filepath.Join(dir, file.Name()))
		if err != nil {
			log.Printf("error reading file %s/%s: %v", dir, file, err)
			continue
		}

		regoHelpers = append(regoHelpers, string(helperCode))
	}

	for _, file := range files {
		if isHelper(file.Name()) {
			continue
		}
		regoCode, err := ioutil.ReadFile(filepath.Join(dir, file.Name()))
		if err != nil {
			log.Printf("error reading file %s/%s: %v", dir, file, err)
			continue
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
			continue
		}
		res = append(res, sig)
	}
	return res, nil
}

func isHelper(name string) bool {
	return strings.HasSuffix(name, "helpers.rego")
}
