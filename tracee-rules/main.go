package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/aquasecurity/tracee/tracee-rules/signatures/rego/regosig"

	"oras.land/oras-go/pkg/oras"

	"github.com/aquasecurity/tracee/tracee-rules/engine"
	"github.com/aquasecurity/tracee/tracee-rules/types"
	"github.com/open-policy-agent/opa/compile"
	"github.com/urfave/cli/v2"

	"oras.land/oras-go/pkg/content"
)

const (
	layerMediaTypeTarGz = "application/vnd.cncf.openpolicyagent.layer.v1.tar+gzip"
	layerMediaTypeJson  = "application/vnd.cncf.openpolicyagent.config.v1+json"
	bundleVersion       = ":latest"
	bundleRepository    = "ghcr.io/github.com/simar7/tracee-rules"
)

func main() {
	app := &cli.App{
		Name:  "tracee-rules",
		Usage: "A rule engine for Runtime Security",
		Action: func(c *cli.Context) error {

			if c.NumFlags() == 0 {
				cli.ShowAppHelp(c)
				return errors.New("no flags specified")
			}

			if c.Bool("pprof") {
				mux := http.NewServeMux()
				mux.HandleFunc("/debug/pprof/", pprof.Index)
				mux.Handle("/debug/pprof/allocs", pprof.Handler("allocs"))
				mux.Handle("/debug/pprof/block", pprof.Handler("block"))
				mux.Handle("/debug/pprof/heap", pprof.Handler("heap"))
				mux.Handle("/debug/pprof/mutex", pprof.Handler("mutex"))
				mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
				mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
				mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
				mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
				go func() {
					addr := c.String("pprof-addr")
					fmt.Fprintf(os.Stdout, "Serving pprof endpoints at %s\n", addr)
					if err := http.ListenAndServe(addr, mux); err != http.ErrServerClosed {
						fmt.Fprintf(os.Stderr, "Error serving pprof endpoints: %v\n", err)
					}
				}()
			}

			var target string
			switch strings.ToLower(c.String("rego-runtime-target")) {
			case "wasm":
				return errors.New("target unsupported: " + target)
			case "rego":
				target = compile.TargetRego
			default:
				return errors.New("invalid target specified " + target)
			}

			eSigs, err := getSignatures(target, c.Bool("rego-partial-eval"), c.String("rules-dir"), c.StringSlice("rules"), c.Bool("rego-aio"))
			if err != nil {
				return err
			}
			var nSigs []types.Signature
			if c.Bool("fetch-latest-sigs") {
				log.Println("Fetching latest sigs from: ", bundleRepository)
				reg, err := content.NewRegistry(content.RegistryOptions{})
				if err != nil {
					return fmt.Errorf("unable to initialize OCI registry: %s", err)
				}
				bundle, err := fetchLatestBundle(reg)
				if err != nil {
					return fmt.Errorf("unable to fetch new sigs: %s", err)
				}
				gzf, err := extractGzip(bundle)
				if err != nil {
					return err
				}
				nSigs, err = untarSigs(target, c.Bool("rego-partial-eval"), gzf)
				if err != nil {
					return err
				}
			}

			// de-dup all existing and newly fetched sigs, if any.
			sigs := dedupSigs(eSigs, nSigs)

			var loadedSigIDs []string
			for _, s := range sigs {
				m, err := s.GetMetadata()
				if err != nil {
					log.Printf("failed to load signature: %v", err)
					continue
				}
				loadedSigIDs = append(loadedSigIDs, m.ID)
			}

			if c.Bool("list-events") {
				listEvents(os.Stdout, sigs)
				return nil
			}

			fmt.Printf("Loaded %d signature(s): %s\n", len(loadedSigIDs), loadedSigIDs)

			if c.Bool("list") {
				return listSigs(os.Stdout, sigs)
			}

			var inputs engine.EventSources
			opts, err := parseTraceeInputOptions(c.StringSlice("input-tracee"))
			if err == errHelp {
				printHelp()
				return nil
			}
			if err != nil {
				return err
			}
			inputs.Tracee, err = setupTraceeInputSource(opts)
			if err != nil {
				return err
			}

			output, err := setupOutput(os.Stdout, c.String("webhook"), c.String("webhook-template"), c.String("webhook-content-type"), c.String("output-template"))
			if err != nil {
				return err
			}
			e, err := engine.NewEngine(sigs, inputs, output, os.Stderr, c.Bool("rego-enable-parsed-events"))
			if err != nil {
				return fmt.Errorf("constructing engine: %w", err)
			}
			e.Start(sigHandler())
			return nil
		},
		Flags: []cli.Flag{
			&cli.StringSliceFlag{
				Name:  "rules",
				Usage: "select which rules to load. Specify multiple rules by repeating this flag. Use --list for rules to select from",
			},
			&cli.StringFlag{
				Name:  "rules-dir",
				Usage: "directory where to search for rules in OPA (.rego) or Go plugin (.so) formats",
			},
			&cli.BoolFlag{
				Name:  "rego-partial-eval",
				Usage: "enable partial evaluation of rego rules",
			},
			&cli.BoolFlag{
				Name:  "list",
				Usage: "print all available rules",
			},
			&cli.StringFlag{
				Name:  "webhook",
				Usage: "HTTP endpoint to call for every match",
			},
			&cli.StringFlag{
				Name:  "webhook-template",
				Usage: "path to a gotemplate for formatting webhook output",
			},
			&cli.StringFlag{
				Name:  "webhook-content-type",
				Usage: "content type of the template in use. Recommended if using --webhook-template",
			},
			&cli.StringSliceFlag{
				Name:  "input-tracee",
				Usage: "configure tracee-ebpf as input source. see '--input-tracee help' for more info",
			},
			&cli.StringFlag{
				Name:  "output-template",
				Usage: "configure output format via templates. Usage: --output-template=path/to/my.tmpl",
			},
			&cli.BoolFlag{
				Name:  "pprof",
				Usage: "enables pprof endpoints",
			},
			&cli.StringFlag{
				Name:  "pprof-addr",
				Usage: "listening address of the pprof endpoints server",
				Value: ":7777",
			},
			&cli.BoolFlag{
				Name:  "rego-enable-parsed-events",
				Usage: "enables pre parsing of input events to rego prior to evaluation",
			},
			&cli.BoolFlag{
				Name:  "rego-aio",
				Usage: "compile rego signatures altogether as an aggregate policy. By default each signature is compiled separately.",
			},
			&cli.StringFlag{
				Name:  "rego-runtime-target",
				Usage: "select which runtime target to use for evaluation of rego rules: rego, wasm",
				Value: "rego",
			},
			&cli.BoolFlag{
				Name:  "list-events",
				Usage: "print a list of events that currently loaded signatures require",
			},
			&cli.BoolFlag{
				Name:  "fetch-latest-sigs",
				Usage: "fetches the latest set of available rego sgnature bundle",
			},
		},
	}
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func dedupSigs(eSigs []types.Signature, nSigs []types.Signature) []types.Signature {
	sigsMap := make(map[string]types.Signature)
	for _, es := range eSigs {
		esm, _ := es.GetMetadata()
		sigsMap[esm.ID] = es
	}
	for _, ns := range nSigs {
		nsm, _ := ns.GetMetadata()
		sigsMap[nsm.ID] = ns
	}

	var sigs []types.Signature
	for _, sig := range sigsMap {
		sigs = append(sigs, sig)
	}
	return sigs
}

func fetchLatestBundle(reg *content.Registry) ([]byte, error) { // TODO: Write tests
	store := content.NewMemory()
	_, err := oras.Copy(context.Background(), reg, bundleRepository+bundleVersion, store, bundleRepository+bundleVersion, oras.WithAllowedMediaTypes([]string{layerMediaTypeTarGz, layerMediaTypeJson}))
	if err != nil {
		return nil, err
	}

	_, b, ok := store.GetByName("bundle.tar.gz")
	if !ok {
		return nil, fmt.Errorf("invalid rule bundle")
	}

	return b, nil
}

func extractGzip(bundle []byte) (io.Reader, error) {
	gzf, err := gzip.NewReader(bytes.NewReader(bundle))
	if err != nil {
		return nil, fmt.Errorf("unable to read: %s", err)
	}
	return gzf, nil
}

func untarSigs(target string, partialEval bool, gzf io.Reader) ([]types.Signature, error) {
	var sigs []types.Signature
	tarReader := tar.NewReader(gzf)
	i := 0
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("unable to read tar: %s", err)
		}

		name := header.Name
		switch header.Typeflag {
		case tar.TypeDir:
			continue
		case tar.TypeReg:
			if strings.Contains(name, "rego") && !strings.Contains(name, "test") {
				regoCode, err := ioutil.ReadAll(tarReader)
				if err != nil {
					log.Println("unable to read file: ", name, err)
					continue
				}
				regoHelpers := []string{regoHelpersCode}
				sig, err := regosig.NewRegoSignature(target, partialEval, append(regoHelpers, string(regoCode))...)
				if err != nil {
					log.Println("unable to create sig: ", err)
					continue
				}
				sigs = append(sigs, sig)
			}
		}
		i++
	}
	return sigs, nil
}

func listSigs(w io.Writer, sigs []types.Signature) error {
	fmt.Fprintf(w, "%-10s %-35s %s %s\n", "ID", "NAME", "VERSION", "DESCRIPTION")
	for _, sig := range sigs {
		meta, err := sig.GetMetadata()
		if err != nil {
			continue
		}
		fmt.Fprintf(w, "%-10s %-35s %-7s %s\n", meta.ID, meta.Name, meta.Version, meta.Description)
	}
	return nil
}

func listEvents(w io.Writer, sigs []types.Signature) {
	var events []string
	for _, sig := range sigs {
		es, _ := sig.GetSelectedEvents()
		for _, e := range es {
			events = append(events, e.Name)
		}
	}
	fmt.Fprintln(w, strings.Join(events, ","))
}

func sigHandler() chan bool {
	sigs := make(chan os.Signal, 1)
	done := make(chan bool, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		done <- true
	}()
	return done
}
