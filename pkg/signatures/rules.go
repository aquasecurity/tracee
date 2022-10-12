package signatures

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/aquasecurity/tracee/types/detect"
)

func ListEvents(w io.Writer, sigs []detect.Signature) {
	m := make(map[string]struct{})
	for _, sig := range sigs {
		es, _ := sig.GetSelectedEvents()
		for _, e := range es {
			if _, ok := m[e.Name]; !ok {
				m[e.Name] = struct{}{}
			}
		}
	}

	var events []string
	for k := range m {
		events = append(events, k)
	}

	sort.Slice(events, func(i, j int) bool { return events[i] < events[j] })
	fmt.Fprintln(w, strings.Join(events, ","))
}
