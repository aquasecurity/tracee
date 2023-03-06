package sets_test

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/tracee/pkg/filters/sets"
)

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func RandStringRunes(n int, prefixes []string) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	if rand.Intn(10) > 5 {
		return string(b)
	}
	return prefixes[rand.Intn(len(prefixes))] + string(b)
}

func Test_PrefixSet(t *testing.T) {
	prefixes := sets.NewPrefixSet()
	put := []string{
		"bruh",
		"ahi",
		"yallla",
		"/etc/",
		"/home/",
		"/tmp/",
		"/bin/x",
		"lib",
		"xlib64",
		"/usr",
	}
	for _, val := range put {
		prefixes.Put(val)
	}

	inputs := []string{"xlib643", "/x/bin/x/a2", "/bin/x/a3", "bruh5", "abruh6", "yallla", "yalla", "/home/ubuntu", "/dir/home/ubuntu"}
	res := []bool{}
	expected := []bool{true, false, true, true, false, true, false, true, false}

	for n := 0; n < len(inputs); n++ {
		res = append(res, prefixes.Filter(inputs[n]))
	}

	assert.ElementsMatch(t, expected, res)
}

func Test_SuffixSet(t *testing.T) {
	suffixes := sets.NewSuffixSet()
	put := []string{
		"bruh",
		"ahi",
		"/.ssh",
		"/kube.config",
		"/.git",
		".git",
	}
	for _, val := range put {
		suffixes.Put(val)
	}

	inputs := []string{"abruh", "bruh", "bruh5", "/home/ubuntu/.ssh", "/usr/kubernetes/kube.config", "k8s/kube.config.user", "/path/to/repo/.git", "path/to/repo/.gitignore"}
	res := []bool{}
	expected := []bool{true, true, false, true, true, false, true, false}

	for n := 0; n < len(inputs); n++ {
		res = append(res, suffixes.Filter(inputs[n]))
	}

	assert.ElementsMatch(t, expected, res)
}
