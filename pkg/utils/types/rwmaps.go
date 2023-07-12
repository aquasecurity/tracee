package types

import (
	"sync"

	"golang.org/x/exp/maps"
)

// RWMap is a map envelopment for concurrent map use
type RWMap[K comparable, V any] struct {
	m     map[K]V
	mutex *sync.RWMutex
}

func InitRWMap[K comparable, V any]() RWMap[K, V] {
	return RWMap[K, V]{
		m:     make(map[K]V),
		mutex: &sync.RWMutex{},
	}
}

func EnvelopeMapWithRW[K comparable, V any](m map[K]V) RWMap[K, V] {
	return RWMap[K, V]{
		m:     m,
		mutex: &sync.RWMutex{},
	}
}

func (m *RWMap[K, V]) Get(k K) (V, bool) {
	m.mutex.RLock()
	v, found := m.m[k]
	m.mutex.RUnlock()
	return v, found
}

func (m *RWMap[K, V]) Set(k K, v V) {
	m.mutex.Lock()
	m.m[k] = v
	m.mutex.Unlock()
}

func (m *RWMap[K, V]) Delete(k K) {
	m.mutex.Lock()
	delete(m.m, k)
	m.mutex.Unlock()
}

func (m *RWMap[K, V]) Keys() []K {
	m.mutex.RLock()
	keys := maps.Keys[map[K]V](m.m)
	m.mutex.RUnlock()
	return keys
}

func (m *RWMap[K, V]) Values() []V {
	m.mutex.RLock()
	values := maps.Values[map[K]V](m.m)
	m.mutex.RUnlock()
	return values
}

func (m *RWMap[K, V]) Clear() {
	m.mutex.Lock()
	maps.Clear[map[K]V](m.m)
	m.mutex.Unlock()
}

func (m *RWMap[K, V]) Len() int {
	m.mutex.RLock()
	mapLen := len(m.m)
	m.mutex.RUnlock()
	return mapLen
}
