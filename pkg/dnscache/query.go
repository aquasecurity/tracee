package dnscache

import (
	"fmt"
	"time"

	"golang.org/x/exp/slices"

	"github.com/aquasecurity/tracee/pkg/logger"
)

type cacheQuery struct {
	dnsResults []string
	ipResults  []string
}

func (q *cacheQuery) String() string {
	return fmt.Sprintf("DNS: %s\nIP: %s", q.dnsResults, q.ipResults)
}

func (q *cacheQuery) DNSResults() []string {
	dst := make([]string, len(q.dnsResults))
	copy(dst, q.dnsResults)
	return dst
}

func (q *cacheQuery) IPResults() []string {
	dst := make([]string, len(q.ipResults))
	copy(dst, q.ipResults)
	return dst
}

// addNodeToQueryResult adds a node's children to a query result object
func (nc *DNSCache) addNodeChildrenToQueryResult(node *dnsNode, query *cacheQuery, queryTime time.Time) {
	if node.next == nil {
		return
	}
	for _, child := range node.next.ItemsMutable() {
		if queryTime.After(node.expiredAfter) {
			// skip expired item
			continue
		}
		// children should be appended in the query result list
		err := nc.addSingleNodeToQueryResult(child, query, false)
		if err != nil {
			logger.Errorw("error adding node to dns cache", "error", err)
		}
		nc.addNodeChildrenToQueryResult(child, query, queryTime)
	}
}

// addNodeToQueryResult adds a node's parents to a query result object.
// It also bumps the root parents in the LRU once reached.
func (nc *DNSCache) addNodeParentsToQueryResult(node *dnsNode, query *cacheQuery, queryTime time.Time) {
	if node.parents == nil {
		return
	}
	if node.parents.Length() == 0 {
		// no parents means a query root, bump it in the LRU
		_, _ = nc.queryRoots.Get(node.value)
	}
	for _, parent := range node.parents.ItemsMutable() {
		if queryTime.After(node.expiredAfter) {
			// skip expired item
			continue
		}
		// parents should be prepended in the query result list
		err := nc.addSingleNodeToQueryResult(parent, query, true)
		if err != nil {
			logger.Errorw("error adding node to dns cache", "error", err)
		}
		nc.addNodeParentsToQueryResult(parent, query, queryTime)
	}
}

// addSingleNodeToQueryResult adds the data of a single node to a query result objehout
func (nc *DNSCache) addSingleNodeToQueryResult(node *dnsNode, query *cacheQuery, doPrepend bool) error {
	switch node.nodeType {
	case DNS:
		sliceAppendOrPrepend(&query.dnsResults, node.value, doPrepend)
	case IP:
		sliceAppendOrPrepend(&query.ipResults, node.value, doPrepend)
	default:
		return fmt.Errorf("invalid node type: %d", node.nodeType)
	}
	return nil
}

func sliceAppendOrPrepend[T comparable](arr *[]T, value T, isPrepend bool) {
	if isPrepend {
		*arr = slices.Insert(*arr, 0, value)
	} else {
		*arr = append(*arr, value)
	}
}
