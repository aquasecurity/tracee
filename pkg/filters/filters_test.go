package filters_test

import (
	"fmt"
	"testing"

	"github.com/aquasecurity/tracee/pkg/filters"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/stretchr/testify/assert"
)

func TestIntFilter(t *testing.T) {
	testCases := []struct {
		name         string
		filterInputs []protocol.Filter
		vals         []int64
		expected     []bool
	}{
		{
			name: "simple equality checks",
			filterInputs: []protocol.Filter{
				{
					Field:    "test",
					Operator: protocol.Equal,
					Value:    []interface{}{50, -2, 8},
				},
			},
			vals:     []int64{50, -2, 8, -4, 51},
			expected: []bool{true, true, true, false, false},
		},
		{
			name: "conflict - same equal and non equal",
			filterInputs: []protocol.Filter{
				{
					Field:    "test",
					Operator: protocol.Equal,
					Value:    []interface{}{50, 8},
				},
				{
					Field:    "test",
					Operator: protocol.NotEqual,
					Value:    []interface{}{50},
				},
			},
			vals:     []int64{50, -2, 8, -4, 51},
			expected: []bool{true, false, true, false, false},
		},
		{
			name: "excluding greater and lower, with equals in between",
			filterInputs: []protocol.Filter{
				{
					Field:    "test",
					Operator: protocol.Greater,
					Value:    []interface{}{50},
				},
				{
					Field:    "test",
					Operator: protocol.Lower,
					Value:    []interface{}{-2},
				},
				{
					Field:    "test",
					Operator: protocol.Equal,
					Value:    []interface{}{8},
				},
			},
			vals:     []int64{50, -2, 8, -4, 51},
			expected: []bool{false, false, true, true, true},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			filter, err := filters.NewIntFilter(tc.filterInputs...)
			if err != nil {
				t.Fail()
			}
			result := make([]bool, len(tc.vals))
			for i, val := range tc.vals {
				result[i] = filter.Filter(val)
			}
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestUIntFilter(t *testing.T) {
	testCases := []struct {
		name         string
		filterInputs []protocol.Filter
		vals         []uint64
		expected     []bool
	}{
		{
			name: "simple equality checks",
			filterInputs: []protocol.Filter{
				{
					Field:    "test",
					Operator: protocol.Equal,
					Value:    []interface{}{50, 7, 8},
				},
			},
			vals:     []uint64{50, 149, 7, 8},
			expected: []bool{true, false, true, true},
		},
		{
			name: "conflict - same equal and non equal",
			filterInputs: []protocol.Filter{
				{
					Field:    "test",
					Operator: protocol.Equal,
					Value:    []interface{}{50, 8},
				},
				{
					Field:    "test",
					Operator: protocol.NotEqual,
					Value:    []interface{}{50},
				},
			},
			vals:     []uint64{50, 149, 7, 8},
			expected: []bool{true, false, false, true},
		},
		{
			name: "excluding greater and lower, with equals in between",
			filterInputs: []protocol.Filter{
				{
					Field:    "test",
					Operator: protocol.Greater,
					Value:    []interface{}{50, 51},
				},
				{
					Field:    "test",
					Operator: protocol.Lower,
					Value:    []interface{}{4},
				},
				{
					Field:    "test",
					Operator: protocol.Equal,
					Value:    []interface{}{8},
				},
			},
			vals:     []uint64{50, 4, 8, 2, 51, 52},
			expected: []bool{false, false, true, true, true, true},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			filter, err := filters.NewUIntFilter(tc.filterInputs...)
			if err != nil {
				t.Fail()
			}
			result := make([]bool, len(tc.vals))
			for i, val := range tc.vals {
				result[i] = filter.Filter(val)
			}
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestStringFilter(t *testing.T) {
	testCases := []struct {
		name         string
		filterInputs []protocol.Filter
		vals         []string
		expected     []bool
		expectedErr  error
	}{
		{
			name: "normal case - only equality",
			filterInputs: []protocol.Filter{
				{
					Field:    "test",
					Operator: protocol.Equal,
					Value:    []interface{}{"abc", "abcd"},
				},
			},
			vals:     []string{"abc", "abcd", "abcde", "aaaaaa"},
			expected: []bool{true, true, false, false},
		},
		{
			name: "normal case - only non equals",
			filterInputs: []protocol.Filter{
				{
					Field:    "test",
					Operator: protocol.NotEqual,
					Value:    []interface{}{"abc", "abcd"},
				},
			},
			vals:     []string{"abc", "abcd", "abcde", "aaaaaa"},
			expected: []bool{false, false, true, true},
		},
		{
			name: "conflict - same equal and not equal",
			filterInputs: []protocol.Filter{
				{
					Field:    "test",
					Operator: protocol.NotEqual,
					Value:    []interface{}{"abc", "abcd"},
				},
				{
					Field:    "test",
					Operator: protocol.Equal,
					Value:    []interface{}{"abc"},
				},
			},
			vals:     []string{"abc", "abcd", "abcde", "aaaaaa"},
			expected: []bool{true, false, true, true},
		},
		{
			name: "real example - from signature filters",
			filterInputs: []protocol.Filter{
				{
					Field:    "test",
					Operator: protocol.NotEqual,
					Value:    []interface{}{"flanneld", "kube-proxy", "etcd", "kube-apiserver", "coredns", "kube-controller", "kubectl"},
				},
				{
					Field:    "test",
					Operator: protocol.Equal,
					Value:    []interface{}{"kube-apiserver", "kubelet", "kube-controller", "etcd"},
				},
			},
			vals:     []string{"flanneld", "kube-proxy", "etcd", "kube-apiserver", "coredns", "kube-controller", "kubectl", "kubelet", "bruh"},
			expected: []bool{false, false, true, true, false, true, false, true, true},
		},
		{
			name: "real example - test prefix, suffix and contains",
			filterInputs: []protocol.Filter{
				{
					Field:    "test",
					Operator: protocol.Equal,
					Value:    []interface{}{"*/release_agent", "/etc/kubernetes/pki/*", "*secrets/kubernetes.io/serviceaccount*", "*token", "/etc/ld.so.preload"},
				},
			},
			vals: []string{
				"xd/bruh/release_agent",
				"/etc/kubernetes/pki/true",
				"/nottrue/etc/kubernetes/pki/",
				"anythingheresecrets/kubernetes.io/serviceaccountanythingthere",
				"secrets/kubernetes.io/serviceaccount",
				"secrets/notkubernetes.io/serviceaccount",
				"token",
				"something_token",
				"token_withsomething",
				"/etc/ld.so.preload",
				"/etc/ld.so..preload",
			},
			expected: []bool{true, true, false, true, true, false, true, true, false, true, false},
		},
		{
			name: "error - unsupported operator GreaterEqual",
			filterInputs: []protocol.Filter{
				{
					Field:    "test",
					Operator: protocol.GreaterEqual,
					Value:    []interface{}{"*/release_agent", "/etc/kubernetes/pki/*", "*secrets/kubernetes.io/serviceaccount*", "*token", "/etc/ld.so.preload"},
				},
			},
			expectedErr: filters.UnsupportedOperator(filters.GreaterEqual),
		},
		{
			name: "error - equal double wildcard",
			filterInputs: []protocol.Filter{
				{
					Field:    "test",
					Operator: protocol.Equal,
					Value:    []interface{}{"**"},
				},
			},
			expected:    []bool{},
			expectedErr: fmt.Errorf("invalid wildcard value **"),
		},
		{
			name: "error - equal single wildcard",
			filterInputs: []protocol.Filter{
				{
					Field:    "test",
					Operator: protocol.Equal,
					Value:    []interface{}{"*"},
				},
			},
			expected:    []bool{},
			expectedErr: fmt.Errorf("invalid wildcard value *"),
		},
		{
			name: "error - not equal double wildcard",
			filterInputs: []protocol.Filter{
				{
					Field:    "test",
					Operator: protocol.NotEqual,
					Value:    []interface{}{"**"},
				},
			},
			expected:    []bool{},
			expectedErr: fmt.Errorf("invalid wildcard value **"),
		},
		{
			name: "error - not equal single wildcard",
			filterInputs: []protocol.Filter{
				{
					Field:    "test",
					Operator: protocol.NotEqual,
					Value:    []interface{}{"*"},
				},
			},
			expected:    []bool{},
			expectedErr: fmt.Errorf("invalid wildcard value *"),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			filter, err := filters.NewStringFilter(tc.filterInputs...)
			if tc.expectedErr != nil {
				assert.Equal(t, tc.expectedErr, err)
			} else {
				result := make([]bool, len(tc.vals))
				for i, val := range tc.vals {
					result[i] = filter.Filter(val)
				}
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}
