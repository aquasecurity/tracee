package dnscache

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"

	"github.com/aquasecurity/tracee/pkg/events/parse"
	"github.com/aquasecurity/tracee/types/trace"
)

const (
	reverseQueryIPv4Suffix = ".in-addr.arpa"
	reverseQueryIPv6Suffix = ".ip6.arpa"
	DefaultCacheSize       = 5000 // default size for maximum query roots in the cache (more nodes are possible)
)

var ErrDNSRecordNotFound = errors.New("no such dns record")
var ErrDNSRecordExpired = errors.New("dns record expired")

type DNSCache struct {
	queryRoots   *lru.Cache[string, *dnsNode]
	queryIndices map[string]*dnsNode

	lock *sync.RWMutex
}

type Config struct {
	CacheSize int
	Enable    bool
}

func New(config Config) (*DNSCache, error) {
	nc := &DNSCache{}
	var err error
	nc.queryRoots, err = lru.NewWithEvict[string, *dnsNode](config.CacheSize, nc.evictQueryRoot)
	if err != nil {
		return nil, err
	}
	nc.queryIndices = make(map[string]*dnsNode)
	nc.lock = new(sync.RWMutex)
	return nc, nil
}

func (nc *DNSCache) Add(event *trace.Event) error {
	// parse dns argument
	dns, err := parse.ArgVal[trace.ProtoDNS](event.Args, "proto_dns")
	if err != nil {
		return err
	}

	// discover if it is a request or response

	if dns.QR != 1 || len(dns.Answers) < 1 {
		return nil // not a dns response
	}

	if len(dns.Questions) != 1 {
		return fmt.Errorf("wrong number of requests found")
	}

	// transaction lock
	nc.lock.Lock()
	defer nc.lock.Unlock()

	question := dns.Questions[0].Name
	questionNode, ok := nc.queryIndices[question]
	eventUnixTimestamp := time.Unix(0, int64(event.Timestamp))

	// Check if question is indexed in the tree...
	if !ok {
		nc.addRootNode(&dns, eventUnixTimestamp)
	} else {
		nc.addChildNodes(dns.Answers, questionNode, eventUnixTimestamp)
	}
	return nil
}

// Get returns all parent and child DNS records relative to the given record value.
// Note, that the query does not traverse the tree downwards from the parent nodes.
func (nc *DNSCache) Get(key string) (cacheQuery, error) {
	nc.lock.RLock()
	defer nc.lock.RUnlock()

	// in case of query with reverse query syntax, sanitize the input
	key = strings.TrimSuffix(key, reverseQueryIPv4Suffix)
	key = strings.TrimSuffix(key, reverseQueryIPv6Suffix)

	// check existance
	node, ok := nc.queryIndices[key]
	if !ok {
		return cacheQuery{}, ErrDNSRecordNotFound
	}

	queryResult := cacheQuery{
		dnsResults: []string{},
		ipResults:  []string{},
	}

	queryTime := time.Now()

	// check if the requested node is expired
	if queryTime.After(node.expiredAfter) {
		return cacheQuery{}, ErrDNSRecordExpired
	}

	// traverse the graph for all other relevant nodes
	err := nc.addSingleNodeToQueryResult(node, &queryResult, false)
	if err != nil {
		return queryResult, err
	}
	nc.addNodeChildrenToQueryResult(node, &queryResult, queryTime)
	nc.addNodeParentsToQueryResult(node, &queryResult, queryTime)

	return queryResult, nil
}

// addRootNode adds a new root node for DNS queries
func (nc *DNSCache) addRootNode(dns *trace.ProtoDNS, timestamp time.Time) {
	nodeType := DNS
	value := dns.Questions[0].Name
	if dns.Questions[0].Type == "PTR" {
		// handle reverse query case
		nodeType = IP
		// trim whatever suffix is appended (can't know which ip version solely from PTR record)
		value = strings.TrimSuffix(value, reverseQueryIPv4Suffix)
		value = strings.TrimSuffix(value, reverseQueryIPv6Suffix)
	}

	// maximum value for time.Time in go
	// this is used so root nodes will never expire
	maxTime := time.Unix(1<<63-62135596801, 999999999)

	// build the root node
	node := &dnsNode{
		value:        value,
		nodeType:     nodeType,
		next:         newNodeSet(),
		parents:      newNodeSet(),
		expiredAfter: maxTime,
	}

	// index it
	nc.queryIndices[node.value] = node
	nc.queryRoots.Add(node.value, node)
	// build and index its child nodes
	nc.addChildNodes(dns.Answers, node, timestamp)
}

// addChildNodes builds new DNS nodes from a ProtoDNS object and attaches them to a parent node
func (nc *DNSCache) addChildNodes(answers []trace.ProtoDNSResourceRecord, parent *dnsNode, timestamp time.Time) {
	for _, answer := range answers {
		// Check if there is another parent node based on the answer name.
		// For example in A/AAAA queries the answers may include first the CNAME,
		// and then actual IP records related to the CNAME in the name.
		// If the answer's name isn't checked then we may wrongly relate to the original
		// query and not the CNAME.
		contextParent := parent
		actualParentName := answer.Name
		if contextParent.value != actualParentName {
			actualParentNode, ok := nc.queryIndices[actualParentName]
			if ok {
				// switch parent if possible, otherwise stick with the original
				contextParent = actualParentNode
			}
		}

		// build a node from the answer and discovered parent
		// (it may be discarded if the node was previously indexed)
		node := makeNodeFromAnswer(contextParent, &answer, timestamp)

		// check if the child node was already indexed
		if child, ok := nc.queryIndices[node.value]; !ok {
			// index it if not...
			nc.queryIndices[node.value] = node
			// ...and add the node
			contextParent.next.Append(node)
		} else {
			// if already indexed register the parent in the child...
			child.parents.Append(contextParent)
			// ...and update its TTL
			child.updateTTL(answer.TTL, timestamp)
		}
	}
}

// evictQueryRoot is the eviction function for the query roots LRU
func (nc *DNSCache) evictQueryRoot(addr string, node *dnsNode) {
	// eviction may sometimes occur in the context of an Add transaction.
	// In these cases locking is unnecessary, since the evict is done in
	// sequence with adding.
	locked := nc.lock.TryLock()
	if locked {
		defer nc.lock.Unlock()
	}

	// recursively traverse the graph and clear it
	nc.clearNode(node)
	// remove references for GC
	node.next = nil
	node.parents = nil
}

// clearNode deletes a node and all it's children node from the node cache
func (nc *DNSCache) clearNode(node *dnsNode) {
	// clear the index
	delete(nc.queryIndices, node.value)
	node.parents = nil
	if node.next == nil {
		return
	}
	for _, child := range node.next.ItemsMutable() {
		nc.clearNode(child)
		delete(nc.queryIndices, child.value)
	}
	node.next = nil
}
