# DNS Cache Data Source

The `DNS Cache` feature allows to tracee build an accurate image of dns and ip relations.
These relations can be queried in signatures through a data source.

## Enabling the Feature

To switch on the `DNS Cache` feature, run the command:

```bash
sudo tracee --output option:sort-events --output json --output option:parse-arguments --dnscache enable --events <event_type>
```

The underlying structure is populated using the core [net_packet_dns](../../../events/builtin/network/net_packet_dns.md) event and its payload.

## Command Line Option

```bash
$ tracee --dnscache help
Select different options for the DNS cache.

Example:
  --dnscache enable  | enable with default values (see below).
  --dnscache size=X  | will cache up to X dns query trees - further queries may be cached regardless (default: 5000).

Use comma OR use the flag multiple times to choose multiple options:
  --dnscache size=A
  --dnscache enable
```

Consider for your usecase, how many query trees would you like to store? If you will frequently check only a few addresses, consider lowering the size.

## Internal Data Organization

From the [data-sources documentation](../overview.md), you'll see that searches use keys. It's a bit like looking up information with a specific tag (or a key=value storage).

The `dns data source` operates straightforwardly. Using `string` keys, which represent some network address (a domain or IP), you can fetch `map[string]string` values as shown below:

```go
    schemaMap := map[string]string{
		"ip_addresses": "[]string",
		"dns_queries":  "[]string",
		"dns_root":     "string",
	}
```

Any address found in the cache, and other related addresses, will be returned in the above structure. Particulary useful is the `dns_root` field, which will store the initial dns query which all other addresses derive from.

## Using the Containers Data Source

> Make sure to read [Golang Signatures](../../../events/custom/golang.md) first.

### Signature Initialization

During the signature initialization, get the containers data source instance:

```go
type e2eDnsDataSource struct {
	cb      detect.SignatureHandler
	dnsData detect.DataSource
}

func (sig *e2eDnsDataSource) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	dnsData, ok := ctx.GetDataSource("tracee", "dns")
	if !ok {
		return fmt.Errorf("dns data source not registered")
	}
	if dnsData.Version() > 1 {
		return fmt.Errorf("dns data source version not supported, please update this signature")
	}
	sig.dnsData = dnsData
	return nil
}
```

Then, to each event being handled, you will `Get()`, from the data source, the information needed.

### On Events

Given the following example:

```go
func (sig *e2eDnsDataSource) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("failed to cast event's payload")
	}

	switch eventObj.EventName {
	case "sched_process_exit":
		if eventObj.Executable.Path != "/usr/bin/ping" {
			return nil // irrelevant code path
		}

		dns, err := sig.dnsData.Get("google.com")
		if err != nil {
			return fmt.Errorf("failed to find dns data in data source: %v", err)
		}

		ipResults, ok := dns["ip_addresses"].([]string)
		if !ok {
			return fmt.Errorf("failed to extract ip results")
		}
		if len(ipResults) < 1 {
			return fmt.Errorf("ip results were empty")
		}

		dnsResults, ok := dns["dns_queries"].([]string)
		if !ok {
			return fmt.Errorf("failed to extract dns results")
		}
		if len(dnsResults) < 1 {
			return fmt.Errorf("dns results were empty")
		}
		if dnsResults[0] != "google.com" {
			return fmt.Errorf("bad dns query: %s", dnsResults[0])
		}

		m, _ := sig.GetMetadata()

		sig.cb(detect.Finding{
			SigMetadata: m,
			Event:       event,
			Data:        map[string]interface{}{},
		})
	}

	return nil
}
```

The above signatures shows usage of the feature in a test signature found in our own e2e tests. The test validates a ping command sent to `google.com`.
