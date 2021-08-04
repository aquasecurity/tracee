package tracee

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPrintUint32IP(t *testing.T) {
	var input uint32 = 3232238339
	ip := PrintUint32IP(input)

	expectedIP := "192.168.11.3"
	assert.Equal(t, expectedIP, ip)
}

func TestPrint16BytesSliceIP(t *testing.T) {
	input := []byte{32, 1, 13, 184, 133, 163, 0, 0, 0, 0, 138, 46, 3, 112, 115, 52}
	ip := Print16BytesSliceIP(input)

	expectedIP := "2001:db8:85a3::8a2e:370:7334"
	assert.Equal(t, expectedIP, ip)
}

func TestPrintAlert(t *testing.T) {
	testCases := []struct {
		name     string
		input    alert
		expected string
	}{
		{"SecurityAlert1", alert{Msg: 1}, "Mmaped region with W+E permissions!"},
		{"SecurityAlert2", alert{Msg: 2}, "Protection changed to Executable!"},
		{"SecurityAlert3", alert{Msg: 3}, "Protection changed from E to W+E!"},
		{"SecurityAlert4", alert{Msg: 4}, "Protection changed from W+E to E!"},
		{"AlertNotDefined", alert{Msg: 5}, "5"},
		{"AlertNotDefinedWithPayload", alert{Msg: 6, Payload: 1, Ts: 1628094500}, "6 Saving data to bin.1628094500"},
	}

	for _, tc := range testCases {
		actual := PrintAlert(tc.input)
		assert.Equal(t, tc.expected, actual, tc.name)
	}
}
