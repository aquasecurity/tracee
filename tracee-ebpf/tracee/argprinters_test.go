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
