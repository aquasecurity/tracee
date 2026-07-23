package runtime

import (
	"context"
	"errors"
	"testing"

	"github.com/containerd/containerd/v2/core/containers"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests exercise the containerd enricher's logic without a running
// containerd daemon by faking the containerd Store interfaces the enricher
// depends on. Because the enricher's fields are the containerd
// containers/images/namespaces Store interfaces, a same-package (white-box)
// test can build the struct directly with fakes - so there is no socket to
// mock and the tests run anywhere (no root, no containerd). This guards the
// enrichment logic and pins it to the containerd v2 Store/Container/Image
// shapes the migration moved to.

var errNotFound = errors.New("not found")

// fakeNamespaceStore implements namespaces.Store, returning a fixed list.
type fakeNamespaceStore struct{ names []string }

func (f *fakeNamespaceStore) Create(context.Context, string, map[string]string) error {
	return nil
}
func (f *fakeNamespaceStore) Labels(context.Context, string) (map[string]string, error) {
	return nil, nil
}
func (f *fakeNamespaceStore) SetLabel(context.Context, string, string, string) error { return nil }
func (f *fakeNamespaceStore) List(context.Context) ([]string, error)                 { return f.names, nil }
func (f *fakeNamespaceStore) Delete(context.Context, string, ...namespaces.DeleteOpts) error {
	return nil
}

// fakeContainerStore implements containers.Store. Get returns a container only
// when the context namespace matches a key in byNamespace, which lets a test
// verify the enricher iterates namespaces until it finds the container.
type fakeContainerStore struct {
	byNamespace map[string]containers.Container
}

func (f *fakeContainerStore) Get(ctx context.Context, id string) (containers.Container, error) {
	ns, _ := namespaces.Namespace(ctx)
	c, ok := f.byNamespace[ns]
	if !ok || c.ID != id {
		return containers.Container{}, errNotFound
	}
	return c, nil
}
func (f *fakeContainerStore) List(context.Context, ...string) ([]containers.Container, error) {
	return nil, nil
}
func (f *fakeContainerStore) Create(_ context.Context, c containers.Container) (containers.Container, error) {
	return c, nil
}
func (f *fakeContainerStore) Update(_ context.Context, c containers.Container, _ ...string) (containers.Container, error) {
	return c, nil
}
func (f *fakeContainerStore) Delete(context.Context, string) error { return nil }

// fakeImageStore implements images.Store, resolving image records by name.
type fakeImageStore struct{ byName map[string]images.Image }

func (f *fakeImageStore) Get(_ context.Context, name string) (images.Image, error) {
	img, ok := f.byName[name]
	if !ok {
		return images.Image{}, errNotFound
	}
	return img, nil
}
func (f *fakeImageStore) List(context.Context, ...string) ([]images.Image, error) { return nil, nil }
func (f *fakeImageStore) Create(_ context.Context, img images.Image) (images.Image, error) {
	return img, nil
}
func (f *fakeImageStore) Update(_ context.Context, img images.Image, _ ...string) (images.Image, error) {
	return img, nil
}
func (f *fakeImageStore) Delete(context.Context, string, ...images.DeleteOpt) error { return nil }

const (
	testContainerID = "abc123def456abc123def456abc1"
	testImageRef    = "public.ecr.aws/docker/library/busybox:1.37.0"
	testImageDigest = "sha256:e3652a00a2fabd16ce889f0aa32c38eec347b997e73bd09e69c962ec7f8732ee"
	testFoundNS     = "k8s.io"
)

// newTestEnricher builds a containerdEnricher backed by fakes. client and
// images_cri are left nil: the store happy-path never dereferences them.
func newTestEnricher(labels map[string]string) *containerdEnricher {
	return &containerdEnricher{
		namespaces: &fakeNamespaceStore{names: []string{"default", testFoundNS}},
		containers: &fakeContainerStore{byNamespace: map[string]containers.Container{
			testFoundNS: {ID: testContainerID, Image: testImageRef, Labels: labels},
		}},
		images: &fakeImageStore{byName: map[string]images.Image{
			testImageRef: {Name: testImageRef, Target: ocispec.Descriptor{Digest: digest.Digest(testImageDigest)}},
		}},
	}
}

func TestContainerdEnricher_Get_StoreEnrichment(t *testing.T) {
	e := newTestEnricher(map[string]string{
		PodNameLabel:                 "mypod",
		PodNamespaceLabel:            "myns",
		PodUIDLabel:                  "myuid",
		ContainerNameLabel:           "mycont",
		ContainerTypeContainerdLabel: "container",
	})

	res, err := e.Get(context.Background(), testContainerID)
	require.NoError(t, err)

	// Image name and digest resolved via the image store.
	assert.Equal(t, testImageRef, res.Image)
	assert.Equal(t, testImageDigest, res.ImageDigest)

	// Pod metadata mapped from CRI labels.
	assert.Equal(t, "mypod", res.PodName)
	assert.Equal(t, "myns", res.Namespace)
	assert.Equal(t, "myuid", res.UID)
	assert.Equal(t, "mycont", res.ContName)
	assert.False(t, res.Sandbox)
}

func TestContainerdEnricher_Get_Sandbox(t *testing.T) {
	e := newTestEnricher(map[string]string{
		ContainerTypeContainerdLabel: "sandbox",
	})

	res, err := e.Get(context.Background(), testContainerID)
	require.NoError(t, err)
	assert.True(t, res.Sandbox, "container with sandbox kind label should be flagged as sandbox")
}

func TestContainerdEnricher_Get_NotFoundInAnyNamespace(t *testing.T) {
	e := &containerdEnricher{
		namespaces: &fakeNamespaceStore{names: []string{"default", testFoundNS}},
		containers: &fakeContainerStore{byNamespace: map[string]containers.Container{}},
		images:     &fakeImageStore{byName: map[string]images.Image{}},
	}

	_, err := e.Get(context.Background(), testContainerID)
	require.Error(t, err, "Get should fail when the container is absent from every namespace")
}

func TestContainerdEnricher_Close_NilSafe(t *testing.T) {
	// A directly-constructed enricher (as in these tests, or a future
	// alternative constructor) has nil client/conn; Close must not panic.
	e := &containerdEnricher{}
	require.NoError(t, e.Close())
}
