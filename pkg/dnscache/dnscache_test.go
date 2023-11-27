package dnscache_test

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"math/rand"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/dnscache"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/types/trace"
)

var eventDump []trace.Event = []trace.Event{}

func init() {
	zippedEventsFile, err := os.OpenFile("./dns_events_test.gz", os.O_RDONLY, os.ModeAppend)
	if err != nil {
		panic(err)
	}
	gzipReader, err := gzip.NewReader(zippedEventsFile)
	if err != nil {
		panic(err)
	}
	defer gzipReader.Close()

	scanner := bufio.NewScanner(gzipReader)
	for scanner.Scan() {
		event := scanner.Bytes()
		var e trace.Event
		err := json.Unmarshal(event, &e)
		if err != nil {
			logger.Errorw("Invalid json in " + string(event) + ": " + err.Error())
		} else {
			eventDump = append(eventDump, e)
		}
	}

}

func TestDnsCacheSync(t *testing.T) {
	dnsCache, err := dnscache.New(dnscache.Config{
		Enable:    true,
		CacheSize: 10000,
	})

	require.NoError(t, err)

	for i := 0; i < len(eventDump); i++ {
		evt := eventDump[i]
		evt.Timestamp = int(time.Now().UnixNano()) // modify the timestamp so expiry/ttl logic won't work
		err = dnsCache.Add(&evt)
		require.NoError(t, err)
	}

	// test from query root down
	res, err := dnsCache.Get("google.com")
	require.NoError(t, err)
	assert.Equal(t, res.DNSResults(), []string{"google.com"})
	assert.ElementsMatch(t, res.IPResults(), []string{
		"142.251.111.113",
		"142.251.111.102",
		"142.251.111.101",
		"142.251.111.139",
		"142.251.111.100",
		"142.251.111.138"},
	)
	res, err = dnsCache.Get("www.cooldictionary.com")
	require.NoError(t, err)
	assert.Equal(t, res.DNSResults(), []string{"www.cooldictionary.com"})
	assert.Equal(t, res.IPResults(), []string{"104.196.52.56"})

	// test from index down
	res, err = dnsCache.Get("a229.g.akamai.net")
	require.NoError(t, err)
	assert.ElementsMatch(t, res.DNSResults(), []string{
		"wdw2.wdpromedia.com", "wdw2.wdpromedia.com.edgesuite.net", "a229.g.akamai.net",
	})

	// test from ip leaves up (other ips will not be included)
	res, err = dnsCache.Get("31.13.66.19")
	require.NoError(t, err)
	assert.ElementsMatch(t, res.DNSResults(), []string{
		"connect.facebook.net", "scontent.xx.fbcdn.net",
	})
	assert.Equal(t, res.IPResults(), []string{"31.13.66.19"})
	res, err = dnsCache.Get("2606:4700:10::6816:1f")
	require.NoError(t, err)
	assert.ElementsMatch(t, res.DNSResults(), []string{"dailymaverick.co.za"})
	assert.Equal(t, res.IPResults(), []string{"2606:4700:10::6816:1f"})

	// test reverse ip query
	res, err = dnsCache.Get("231.92.80.190.in-addr.arpa")
	require.NoError(t, err)
	assert.Equal(t, res.DNSResults(), []string{"231-92-pool.dsl.gol.net.gy"})
	assert.Equal(t, res.IPResults(), []string{"231.92.80.190"})

	// possibly add more tests?
}

func TestDnsCacheStressParallel(t *testing.T) {
	dnsCache, err := dnscache.New(dnscache.Config{
		Enable:    true,
		CacheSize: 100,
	})
	require.NoError(t, err)

	addWg := sync.WaitGroup{}
	addWg.Add(2)
	go func() {
		for i := 0; i < len(eventDump)/2; i++ {
			evt := eventDump[i]
			evt.Timestamp = int(time.Now().UnixNano()) // modify the timestamp so expiry/ttl logic won't work
			err := dnsCache.Add(&evt)
			require.NoError(t, err)
		}
		addWg.Done()
	}()

	go func() {
		for i := len(eventDump)/2 + 1; i < len(eventDump); i++ {
			evt := eventDump[i]
			evt.Timestamp = int(time.Now().UnixNano()) // modify the timestamp so expiry/ttl logic won't work
			err := dnsCache.Add(&evt)
			require.NoError(t, err)
		}
		addWg.Done()
	}()

	for {
		select {
		case <-wrapWait(&addWg):
			goto out
		default:
			inputs := []string{
				"142.251.111.113",
				"142.251.111.102",
				"142.251.111.101",
				"142.251.111.139",
				"142.251.111.100",
				"142.251.111.138",
				"google.com",
				"facebook.com",
				"wdw2.wdpromedia.com",
				"wdw2.wdpromedia.com.edgesuite.net",
				"a229.g.akamai.net",
				"2606:4700:10::6816:1f",
				"231-92-pool.dsl.gol.net.gy",
			}
			dnsCache.Get(inputs[rand.Intn(len(inputs))])
		}
	}

out:
}

// helper function to allow using WaitGroup in a select
func wrapWait(wg *sync.WaitGroup) <-chan struct{} {
	out := make(chan struct{})
	go func() {
		wg.Wait()
		out <- struct{}{}
	}()
	return out
}
