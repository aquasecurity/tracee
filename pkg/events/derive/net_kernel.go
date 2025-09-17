package derive

import (
	"fmt"
	"strings"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/aquasecurity/tracee/common/logger"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/parse"
	"github.com/aquasecurity/tracee/types/trace"
)

//
// Kernel-level Network Events
//
// These events use direct kernel hooks rather than network packet capture,
// providing more reliable and efficient monitoring for specific protocols.
//

func DnsRequestKernel() DeriveFunction {
	return deriveSingleEvent(events.DnsRequestKernel, deriveDnsRequestKernelArgs())
}

func deriveDnsRequestKernelArgs() deriveArgsFunction {
	return func(event *trace.Event) ([]interface{}, error) {
		// Extract the payload from the base event
		payload, err := parse.ArgVal[[]byte](event.Args, "payload")
		if err != nil {
			return nil, fmt.Errorf("failed to extract payload: %w", err)
		}

		var dnsMessageArgs []interface{}

		var p dnsmessage.Parser
		if _, err := p.Start(payload); err != nil {
			// This is expected to happen for DNS messages sent using iovec with iov_len > 1
			logger.Debugw("failed to start DNS message parser", "error", err, "payload", payload)
			return nil, nil
		}

		for {
			q, err := p.Question()
			if err == dnsmessage.ErrSectionDone {
				break
			}
			if err != nil {
				// This is expected to happen for DNS messages sent using iovec with iov_len > 1
				logger.Debugw("failed to parse DNS question", "error", err, "payload", payload)
				break
			}

			hostname := strings.TrimSuffix(q.Name.String(), ".")
			queryType := strings.TrimPrefix(q.Type.String(), "Type")
			dnsMessageArgs = append(dnsMessageArgs, hostname, queryType)
		}

		return dnsMessageArgs, nil
	}
}
