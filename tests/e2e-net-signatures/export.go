package main

import "github.com/aquasecurity/tracee/types/detect"

var ExportedSignatures = []detect.Signature{
	// Network Protocol Events
	&e2eIPv4{},
	&e2eIPv6{},
	&e2eUDP{},
	&e2eTCP{},
	&e2eICMP{},
	&e2eICMPv6{},
	&e2eDNS{},
	&e2eHTTP{},
}

var ExportedDataSources = []detect.DataSource{
	// add data-sources here
}
