package filters_test

import (
	"testing"

	"github.com/aquasecurity/tracee/pkg/filters"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/stretchr/testify/assert"
)

func TestIntFilter(t *testing.T) {
	testCases := []struct {
		name         string
		filter       *filters.IntFilter
		filterInputs []protocol.Filter
		vals         []int64
		expected     []bool
	}{
		{
			name:   "simple equality checks",
			filter: filters.NewIntFilter(),
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
			name:   "conflict - same equal and non equal",
			filter: filters.NewIntFilter(),
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
			name:   "excluding greater and lesser, with equals in between",
			filter: filters.NewIntFilter(),
			filterInputs: []protocol.Filter{
				{
					Field:    "test",
					Operator: protocol.Greater,
					Value:    []interface{}{50},
				},
				{
					Field:    "test",
					Operator: protocol.Lesser,
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
			var err error
			for _, filterReq := range tc.filterInputs {
				err = tc.filter.Add(filterReq)
				if err != nil {
					t.Fail()
				}
			}
			tc.filter.Enable()
			result := make([]bool, len(tc.vals))
			for i, val := range tc.vals {
				result[i] = tc.filter.Filter(val)
			}
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestStringFilter(t *testing.T) {
	testCases := []struct {
		name         string
		filter       *filters.StringFilter
		filterInputs []protocol.Filter
		vals         []string
		expected     []bool
		expectedErr  error
	}{
		{
			name:   "normal case - only equality",
			filter: filters.NewStringFilter(),
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
			name:   "normal case - only non equals",
			filter: filters.NewStringFilter(),
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
			name:   "conflict - same equal and not equal",
			filter: filters.NewStringFilter(),
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
			name:   "real example - from signature filters",
			filter: filters.NewStringFilter(),
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
			name:   "real example - test prefix, suffix and contains",
			filter: filters.NewStringFilter(),
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
			name:   "error - unsupported operator GreaterEqual",
			filter: filters.NewStringFilter(),
			filterInputs: []protocol.Filter{
				{
					Field:    "test",
					Operator: protocol.GreaterEqual,
					Value:    []interface{}{"*/release_agent", "/etc/kubernetes/pki/*", "*secrets/kubernetes.io/serviceaccount*", "*token", "/etc/ld.so.preload"},
				},
			},
			expectedErr: filters.UnsupportedOperator(filters.GreaterEqual),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			for _, filterReq := range tc.filterInputs {
				err = tc.filter.Add(filterReq)
				if err != nil {
					break
				}
			}
			if err != nil {
				assert.Equal(t, tc.expectedErr, err)
			} else {
				tc.filter.Enable()
				result := make([]bool, len(tc.vals))
				for i, val := range tc.vals {
					result[i] = tc.filter.Filter(val)
				}
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}
