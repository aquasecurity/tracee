package sets

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPrefixSet(t *testing.T) {
	t.Parallel()

	prefixes := NewPrefixSet()
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

func TestSuffixSet(t *testing.T) {
	t.Parallel()

	suffixes := NewSuffixSet()
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

func TestPrefixSetClone(t *testing.T) {
	t.Parallel()

	set := NewPrefixSet()
	set.Put("/tmp")

	copy := set.Clone()

	if !reflect.DeepEqual(&set, copy) {
		t.Errorf("Clone did not produce an identical copy")
	}

	// ensure that changes to the copy do not affect the original
	copy.Put("/home")
	if reflect.DeepEqual(&set, copy) {
		t.Errorf("Changes to copied filter affected the original")
	}
}

func TestSuffixSetClone(t *testing.T) {
	t.Parallel()

	set := NewSuffixSet()
	set.Put(".git")

	copy := set.Clone()

	if !reflect.DeepEqual(&set, copy) {
		t.Errorf("Clone did not produce an identical copy")
	}

	// ensure that changes to the copy do not affect the original
	copy.Put(".ssh")
	if reflect.DeepEqual(&set, copy) {
		t.Errorf("Changes to copied filter affected the original")
	}
}
