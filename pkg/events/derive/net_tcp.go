package derive

import (
	"errors"
	"strconv"

	"github.com/aquasecurity/tracee/pkg/dnscache"
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/parse"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/types/trace"
)

// NOTE: Derived from security_socket_XXX events, not from net_packet_XXX ones.

func NetTCPConnect(cache *dnscache.DNSCache) DeriveFunction {
	return deriveSingleEvent(events.NetTCPConnect,
		func(event trace.Event) ([]interface{}, error) {
			dstIP, dstPort, err := pickIpAndPort(event, "remote_addr")
			if err != nil {
				logger.Debugw("error picking address", "error", err)
				return nil, nil
			}
			if dstIP == "" {
				return nil, nil
			}

			// Check if DNS cache is enabled
			results := []string{}
			if cache != nil {
				query, err := cache.Get(dstIP)
				if err != nil {
					switch err {
					case dnscache.ErrDNSRecordNotFound, dnscache.ErrDNSRecordExpired:
						results = []string{}
						goto allGood
					}
					logger.Debugw("ip lookup error", "ip", dstIP, "error", err)
					return nil, nil
				}
				results = query.DNSResults()
			}

		allGood:
			return []interface{}{
				dstIP,
				dstPort,
				results,
			}, nil
		},
	)
}

// pickIpAndPort returns the IP address and port from the event's sockaddr field.
func pickIpAndPort(event trace.Event, fieldName string) (string, int, error) {
	var err error
	// e.g: sockaddr: map[sa_family:AF_INET sin_addr:10.10.11.2 sin_port:1234]

	// Check if socket is a TCP socket.
	sType, err := parse.ArgVal[string](event.Args, "type")
	if err != nil {
		return "", 0, errfmt.WrapError(err)
	}
	if sType != "SOCK_STREAM" {
		return "", 0, nil
	}

	// Get sockaddr field.
	sockaddr, err := parse.ArgVal[map[string]string](event.Args, fieldName)
	if err != nil {
		return "", 0, errfmt.WrapError(err)
	}
	if sockaddr == nil {
		return "", 0, errfmt.WrapError(errors.New("remote_addr not found"))
	}

	var addr string
	var port int

	family, ok := sockaddr["sa_family"]
	if !ok {
		return "", 0, errfmt.WrapError(errors.New("missing field sa_family"))
	}
	switch family {
	case "AF_INET":
		addr, port, err = getAddrAndPort("sin_addr", "sin_port", sockaddr)
		if err != nil {
			return "", 0, errfmt.WrapError(err)
		}
	case "AF_INET6":
		addr, port, err = getAddrAndPort("sin6_addr", "sin6_port", sockaddr)
		if err != nil {
			return "", 0, errfmt.WrapError(err)
		}
	default:
		return "", 0, nil
	}

	return addr, port, nil
}

// getAddrAndPort returns the address and port from sockaddr for IPv4 or IPv6.
func getAddrAndPort(a, p string, sockaddr map[string]string) (string, int, error) {
	for _, key := range []string{a, p} {
		if _, ok := sockaddr[key]; !ok {
			return "", 0, errfmt.WrapError(errors.New("missing field " + key))
		}
	}
	addr := sockaddr[a]
	port, err := strconv.Atoi(sockaddr[p])
	if err != nil {
		return "", 0, errfmt.WrapError(err)
	}
	return addr, port, nil
}
