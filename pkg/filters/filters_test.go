package filters_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/filters"
)

func TestBoolFilter(t *testing.T) {
	testCases := []struct {
		name         string
		expressions  []string
		expected     bool
		filterResult []bool // filter on []bool{true, false}
	}{
		{
			name:         "eval true 1",
			expressions:  []string{"container"},
			expected:     true,
			filterResult: []bool{true, false},
		},
		{
			name:         "eval true 2",
			expressions:  []string{"=true"},
			expected:     true,
			filterResult: []bool{true, false},
		},
		{
			name:         "eval true 3",
			expressions:  []string{"!=false"},
			expected:     true,
			filterResult: []bool{true, false},
		},
		{
			name:         "eval false 1",
			expressions:  []string{"!container"},
			expected:     false,
			filterResult: []bool{false, true},
		},
		{
			name:         "eval false 2",
			expressions:  []string{"=false"},
			expected:     false,
			filterResult: []bool{false, true},
		},
		{
			name:         "eval false 3",
			expressions:  []string{"!=true"},
			expected:     false,
			filterResult: []bool{false, true},
		},
		{
			name:         "eval false then true",
			expressions:  []string{"!container", "=true"},
			expected:     true,
			filterResult: []bool{true, true},
		},
		{
			name:         "no values",
			expressions:  []string{},
			expected:     false,
			filterResult: []bool{false, false},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			filter := filters.NewBoolFilter()
			for _, expr := range tc.expressions {
				err := filter.Parse(expr)
				require.NoError(t, err)
			}

			filter.Enable()

			assert.Equal(t, tc.expected, filter.Value())
			filterRes := []bool{}
			for _, val := range []bool{true, false} {
				filterRes = append(filterRes, filter.Filter(val))
			}
			assert.Equal(t, tc.filterResult, filterRes)
		})
	}
}

func TestIntFilter(t *testing.T) {
	testCases := []struct {
		name        string
		expressions []string
		vals        []int64
		expected    []bool
	}{
		{
			name: "simple equality checks",
			expressions: []string{
				"=50,-2,8",
			},
			vals:     []int64{50, -2, 8, -4, 51},
			expected: []bool{true, true, true, false, false},
		},
		{
			name: "conflict - same equal and non equal",
			expressions: []string{
				"=50,8",
				"!=50",
			},
			vals:     []int64{50, -2, 8, -4, 51},
			expected: []bool{true, false, true, false, false},
		},
		{
			name: "excluding greater and lower, with equals in between",
			expressions: []string{
				">50",
				"<-2",
				"=8",
			},
			vals:     []int64{50, -2, 8, -4, 51},
			expected: []bool{false, false, true, true, true},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			filter := filters.NewIntFilter()
			for _, expr := range tc.expressions {
				err := filter.Parse(expr)
				require.NoError(t, err)
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
		name        string
		expressions []string
		vals        []uint64
		expected    []bool
	}{
		{
			name: "simple equality checks",
			expressions: []string{
				"=50,7,8",
			},
			vals:     []uint64{50, 149, 7, 8},
			expected: []bool{true, false, true, true},
		},
		{
			name: "conflict - same equal and non equal",
			expressions: []string{
				"=50,8",
				"!=50",
			},
			vals:     []uint64{50, 149, 7, 8},
			expected: []bool{true, false, false, true},
		},
		{
			name: "excluding greater and lower, with equals in between",
			expressions: []string{
				">50,51",
				"<4",
				"=8",
			},
			vals:     []uint64{50, 4, 8, 2, 51, 52},
			expected: []bool{false, false, true, true, true, true},
		},
		{
			name: "lower/equal than",
			expressions: []string{
				"<=6",
			},
			vals:     []uint64{6, 5, 4, 7},
			expected: []bool{true, true, true, false},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			filter := filters.NewUIntFilter()
			for _, expr := range tc.expressions {
				err := filter.Parse(expr)
				require.NoError(t, err)
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
		name        string
		expressions []string
		vals        []string
		expected    []bool
		expectedErr error
	}{
		{
			name: "normal case - only equality",
			expressions: []string{
				"=abc,abcd",
			},
			vals:     []string{"abc", "abcd", "abcde", "aaaaaa"},
			expected: []bool{true, true, false, false},
		},
		{
			name: "normal case - only non equals",
			expressions: []string{
				"!=abc,abcd",
			},
			vals:     []string{"abc", "abcd", "abcde", "aaaaaa"},
			expected: []bool{false, false, true, true},
		},
		{
			name: "conflict - same equal and not equal",
			expressions: []string{
				"!=abc,abcd",
				"=abc",
			},
			vals:     []string{"abc", "abcd", "abcde", "aaaaaa"},
			expected: []bool{true, false, true, true},
		},
		{
			name: "real example - from signature filters",
			expressions: []string{
				"!=flanneld,kube-proxy,etcd,kube-apiserver,coredns,kube-controller,kubectl",
				"=kube-apiserver,kubelet,kube-controller,etcd",
			},
			vals:     []string{"flanneld", "kube-proxy", "etcd", "kube-apiserver", "coredns", "kube-controller", "kubectl", "kubelet", "bruh"},
			expected: []bool{false, false, true, true, false, true, false, true, true},
		},
		{
			name: "real example - test prefix, suffix and contains",
			expressions: []string{
				"=*/release_agent,/etc/kubernetes/pki/*,*secrets/kubernetes.io/serviceaccount*,*token,/etc/ld.so.preload",
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
			name: "real  example - security_bprm_check",
			expressions: []string{
				"=mysqld*,postgres*,sqlplus*,couchdb*,memcached*,redis-server*,rabbitmq-server*,mongod*,runc:[2:INIT],nginx*,httpd*,httpd-foregroun*,http-nio*,lighttpd*,apache*,apache2*,runc:*",
				"!=runc*,containerd*,(kubelet)",
			},
			vals: []string{
				"reality", "can", "be", "whatever", "i", "want", "containerd-nothis", "(kubelet)", "runc:[2:INIT]", "runc-else",
			},
			expected: []bool{true, true, true, true, true, true, false, false, true, false},
		},
		{
			name: "error - unsupported operator Greater",
			expressions: []string{
				">*/release_agent,/etc/kubernetes/pki/*,*secrets/kubernetes.io/serviceaccount*,*token,/etc/ld.so.preload",
			},
			expectedErr: filters.UnsupportedOperator(filters.Greater),
		},
		{
			name: "error - equal double wildcard",
			expressions: []string{
				"=**",
			},
			expected:    []bool{},
			expectedErr: filters.InvalidValue("**"),
		},
		{
			name: "error - equal single wildcard",
			expressions: []string{
				"=*",
			},
			expected:    []bool{},
			expectedErr: filters.InvalidValue("*"),
		},
		{
			name: "error - not equal double wildcard",
			expressions: []string{
				"!=**",
			},
			expected:    []bool{},
			expectedErr: filters.InvalidValue("**"),
		},
		{
			name: "error - not equal single wildcard",
			expressions: []string{
				"!=*",
			},
			expected:    []bool{},
			expectedErr: filters.InvalidValue("*"),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			filter := filters.NewStringFilter()
			for _, expr := range tc.expressions {
				err := filter.Parse(expr)
				if tc.expectedErr != nil {
					assert.ErrorContains(t, err, tc.expectedErr.Error())
				}
			}
			if tc.expectedErr == nil {
				result := make([]bool, len(tc.vals))
				for i, val := range tc.vals {
					result[i] = filter.Filter(val)
				}
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}
