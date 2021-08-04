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
