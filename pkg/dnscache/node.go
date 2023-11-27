package dnscache

import (
	"time"

	"github.com/aquasecurity/tracee/pkg/utils/set"
	"github.com/aquasecurity/tracee/types/trace"
)

type nodeType int

const (
	InvalidNode nodeType = iota
	DNS
	IP
)

type dnsNode struct {
	value        string
	nodeType     nodeType
	expiredAfter time.Time
	parents      *set.Set[*dnsNode, string] // maybe this can simply be map[string]*dnsNode?
	next         *set.Set[*dnsNode, string] // ditto
}

func (n *dnsNode) updateTTL(ttl uint32, timestamp time.Time) {
	n.expiredAfter = timestamp.Add(time.Second * time.Duration(ttl))
}

// hashNode serves as a hash function for nodes, used in sets
func hashNode(node *dnsNode) string {
	return node.value
}

// newNodeSet is a helper for building a set data structure for nodes with the relevant hash function
func newNodeSet(nodes ...*dnsNode) *set.Set[*dnsNode, string] {
	return set.NewWithHash(hashNode, nodes...)
}

// makeNodeFromAnswer builds cache nodes from a DNS answer. node may return nil, this case must be handled
func makeNodeFromAnswer(parent *dnsNode, answer *trace.ProtoDNSResourceRecord, timestamp time.Time) *dnsNode {
	nodeType := DNS
	value := ""
	switch answer.Type {
	case "CNAME":
		value = answer.CNAME
	case "A", "AAAA":
		value = answer.IP
		nodeType = IP
	case "MX":
		value = answer.MX.Name
	case "SRV":
		value = answer.SRV.Name
	case "PTR":
		value = answer.PTR
	}
	return &dnsNode{value, nodeType, timestamp.Add(time.Duration(answer.TTL) * time.Second), newNodeSet(parent), newNodeSet()}
}
