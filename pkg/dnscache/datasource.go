package dnscache

import (
	"encoding/json"
	"errors"

	"github.com/aquasecurity/tracee/types/detect"
)

type DNSDatsource struct {
	dns *DNSCache
}

func NewDataSource(d *DNSCache) *DNSDatsource {
	return &DNSDatsource{
		dns: d,
	}
}

func (ctx DNSDatsource) Get(key interface{}) (map[string]interface{}, error) {
	keyString, ok := key.(string)
	if !ok {
		return nil, detect.ErrKeyNotSupported
	}

	query, err := ctx.dns.Get(keyString)

	if errors.Is(err, ErrDNSRecordNotFound) {
		return nil, detect.ErrDataNotFound
	}

	if errors.Is(err, ErrDNSRecordNotFound) {
		return nil, detect.ErrDataNotFound
	}

	if len(query.dnsResults) == 0 && len(query.ipResults) == 0 {
		return nil, detect.ErrDataNotFound
	}

	dnsRoot := ""
	if len(query.dnsResults) > 0 {
		dnsRoot = query.dnsResults[0]
	}

	result := map[string]interface {
	}{
		"ip_addresses": query.ipResults,
		"dns_queries":  query.dnsResults,
		"dns_root":     dnsRoot,
	}

	return result, nil
}

func (ctx DNSDatsource) Keys() []string {
	return []string{"string"}
}

func (ctx DNSDatsource) Schema() string {
	schemaMap := map[string]string{
		"ip_addresses": "[]string",
		"dns_queries":  "[]string",
		"dns_root":     "string",
	}
	schema, _ := json.Marshal(schemaMap)
	return string(schema)
}

func (ctx DNSDatsource) Version() uint {
	return 1
}

func (ctx DNSDatsource) Namespace() string {
	return "tracee"
}

func (ctx DNSDatsource) ID() string {
	return "dns"
}
