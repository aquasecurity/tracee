package elf

import (
	"debug/elf"
	"strings"
	"testing"
)

// Test the instruction finding functions with mock data
func TestFindRetInstsX86_64(t *testing.T) {
	// Simple test with RET instruction (0xC3)
	bytes := []byte{
		0x48, 0x89, 0xe5, // mov %rsp, %rbp
		0xc3, // ret
		0x90, // nop
		0xc3, // ret
	}

	offsets, err := findRetInstsX86_64(0x1000, bytes)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	expected := []uint64{0x1003, 0x1005} // offsets of the RET instructions
	if len(offsets) != len(expected) {
		t.Errorf("Expected %d RET instructions, got %d", len(expected), len(offsets))
	}

	for i, offset := range offsets {
		if offset != expected[i] {
			t.Errorf("Expected offset %d at index %d, got %d", expected[i], i, offset)
		}
	}
}

func TestFindRetInstsX86_64_NoRet(t *testing.T) {
	// Bytes without RET instruction
	bytes := []byte{
		0x48, 0x89, 0xe5, // mov %rsp, %rbp
		0x90, // nop
	}

	_, err := findRetInstsX86_64(0x1000, bytes)
	if err == nil {
		t.Error("Expected error for bytes without RET instruction")
	}
}

func TestFindRetInstsARM64(t *testing.T) {
	// ARM64 RET instruction is 0xd65f03c0 (little-endian: 0xc0, 0x03, 0x5f, 0xd6)
	bytes := []byte{
		0x00, 0x00, 0x80, 0xd2, // mov x0, #0
		0xc0, 0x03, 0x5f, 0xd6, // ret
		0x1f, 0x20, 0x03, 0xd5, // nop
		0xc0, 0x03, 0x5f, 0xd6, // ret
	}

	offsets, err := findRetInstsARM64(0x2000, bytes)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	expected := []uint64{0x2004, 0x200c} // offsets of the RET instructions
	if len(offsets) != len(expected) {
		t.Errorf("Expected %d RET instructions, got %d", len(expected), len(offsets))
	}

	for i, offset := range offsets {
		if offset != expected[i] {
			t.Errorf("Expected offset %d at index %d, got %d", expected[i], i, offset)
		}
	}
}

func TestFindRetInstsARM64_NoRet(t *testing.T) {
	// Bytes without RET instruction
	bytes := []byte{
		0x00, 0x00, 0x80, 0xd2, // mov x0, #0
		0x1f, 0x20, 0x03, 0xd5, // nop
	}

	_, err := findRetInstsARM64(0x2000, bytes)
	if err == nil {
		t.Error("Expected error for bytes without RET instruction")
	}
}

func TestFindRetInsts_UnsupportedArch(t *testing.T) {
	bytes := []byte{0x01, 0x02, 0x03, 0x04}

	_, err := findRetInsts(0x1000, bytes, elf.EM_MIPS)
	if err == nil {
		t.Error("Expected error for unsupported architecture")
	}

	expectedError := "unsupported architecture"
	if err != nil && !strings.Contains(err.Error(), expectedError) {
		t.Errorf("Expected error to contain %q, got %q", expectedError, err.Error())
	}
}

func TestFindRetInsts_SupportedArchs(t *testing.T) {
	// Test that supported architectures call the correct functions
	// We're not testing actual instruction parsing here, just the routing

	tests := []struct {
		arch elf.Machine
		name string
	}{
		{elf.EM_X86_64, "x86_64"},
		{elf.EM_AARCH64, "ARM64"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Empty bytes will cause the underlying functions to fail,
			// but we just want to verify the routing works
			_, err := findRetInsts(0x1000, []byte{}, tt.arch)
			// We expect an error because we passed empty bytes,
			// but it should be from the instruction parser, not "unsupported architecture"
			if err == nil {
				t.Error("Expected error for empty bytes")
			}

			if err != nil && err.Error() == "unsupported architecture MIPS" {
				t.Error("Should not get unsupported architecture error for supported arch")
			}
		})
	}
}
