# Golang Signatures

There are 2 ways you can get your own golang signatures working with tracee.

1. **Built-In Golang signatures**

    !!! Tip
        This is the preferred way to get your own golang signatures integrated
        into Tracee, as you will find in the next part of this page, but it
        needs a better end-user experience (being worked).

    In order to get your golang signature compiled with tracee, you can create
    a file called `signatures/golang/signature_example.go` and place the
    following code in it:

    !!! Signature Example
        ```golang
        package main
        
        import (
        	"fmt"
        	"strings"
        
        	"github.com/aquasecurity/tracee/signatures/helpers"
        	"github.com/aquasecurity/tracee/types/detect"
        	"github.com/aquasecurity/tracee/types/protocol"
        	"github.com/aquasecurity/tracee/types/trace"
        )
        
        type signatureExample struct {
        	cb     detect.SignatureHandler
            logger detect.Logger
        }
        
        func (sig *signatureExample) Init(ctx detect.SignatureContext) error {
        	sig.cb = ctx.Callback
            sig.logger = ctx.Logger
        
        	return nil
        }
        
        func (sig *signatureExample) GetMetadata() (
        	detect.SignatureMetadata,
        	error,
        ) {
        	return detect.SignatureMetadata{
        		ID:          "Mine-0.1.0",
        		Version:     "0.1.0",
        		Name:        "My Own Signature",
        		Description: "My Own Signature Detects Stuff",
        		Tags:        []string{"linux"},
        	}, nil
        }
        
        func (sig *signatureExample) GetSelectedEvents() (
        	[]detect.SignatureEventSelector,
        	error,
        ) {
        
        	return []detect.SignatureEventSelector{
        		{Source: "tracee", Name: "openat"},
        		{Source: "tracee", Name: "execve"},
        	}, nil
        }
        
        func (sig *signatureExample) OnEvent(event protocol.Event) error {
        	switch e := event.Payload.(type) {
        	case trace.Event:
        		if e.ArgsNum == 0 {
                    logger.Debugw("no arguments found")
        			return nil
        		}
        
        		switch e.EventName {
        		case "openat", "execve":
        			arg, err := helpers.GetTraceeArgumentByName(e, "pathname", helpers.GetArgOps{DefaultArgs: false})
        			if err != nil {
        				return err
        			}
        
        			if s, ok := arg.Value.(string); ok {
        				if strings.Contains(s, "/etc/passwd") {
        					m, _ := sig.GetMetadata()
        
        					found := detect.Finding{
        						Event:       event,
        						SigMetadata: m,
        					}
        
        					sig.cb(found)
        				}
        			}
        		}
        	default:
        		return fmt.Errorf("failed to cast event's payload")
        	}
        
        	return nil
        }
        
        func (sig *signatureExample) OnSignal(s detect.Signal) error {
        	return nil
        }
        
        func (sig *signatureExample) Close() {}
        ```

    Then, edit `signatures/golang/export.go` and place your new signature there:

    ```golang
    var ExportedSignatures = []detect.Signature{
        &signatureExample{},
    }
    ```

    Follow instructions on [how to build Tracee] and you will find your new
    signature included in **tracee-rules**. You may even select only the
    signatures you created:

    ```text
    $ sudo ./dist/tracee-ebpf \
        --output json \
        --filter comm=bash \
        --filter follow \
        --output option:parse-arguments \
        -trace event=$(./dist/tracee-rules --rules Mine-0.1.0 --list-events) \
        | ./dist/tracee-rules \
        --input-tracee \
        format:json \
        --input-tracee file:stdin \
        --rules Mine-0.1.0

    Loaded 1 signature(s): [Mine-0.1.0]
    
    *** Detection ***
    Time: 2022-07-10T04:25:44Z
    Signature ID: Mine-0.1.0
    Signature: My Own Signature
    Data: map[]
    Command: batcat
    Hostname: fujitsu
    ```

    **Be creative!** You can create signatures that would do pretty much
    anything! Examples of such signatures would: for every X event, connect to
    a cached external data-source and return a positive detection for cases A,
    B or C.

    [how to build Tracee]: ../../../contributing/building/building.md

2. Create a golang signature plugin and dynamically load it during runtime

    !!! Attention
        Eventually you will find out that Golang Plugins aren't very useful if
        you consider all the problems that emerge from using it:

        1. **Can't use different go versions** (need to compile the go plugin
           with the exact same version that was used to build Tracee).

        2. Both Tracee and your golang plugin signature must be built with the
           **exact same GOPATH** or you will get a "plugin was built with a
           different version of package XXX" error.

        3. Any **dependency** you have in your plugin should be of the **same
           version** with the dependencies of Tracee.

        4. Compiling tracee statically is sometimes useful to have a **complete
           portable eBPF tracing/detection solution**. One good example when
           statically compiling tracee is a good idea is to have a single
           binary capable of running in GLIBC (most of them) and MUSL (Alpine)
           powered Linux distros.

    At the end, creating a golang signature plugin won't have the practical
    effects as a plugin mechanism should have, so it is preferred to have
    built-in golang signatures (re)distributed with newer binaries (when you
    need to add/remove signatures from your environment) **FOR NOW**.
