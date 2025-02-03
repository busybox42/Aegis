// internal/store/local.go
package store

import (
    "errors"
    "sync"
)

type Local struct {
    data map[string][]byte
    mu   sync.RWMutex
}

func NewLocal() *Local {
    return &Local{
        data: make(map[string][]byte),
    }
}

func (s *Local) Store(key []byte, value []byte) error {
    s.mu.Lock()
    defer s.mu.Unlock()
    s.data[string(key)] = value
    return nil
}

func (s *Local) Retrieve(key []byte) ([]byte, error) {
    s.mu.RLock()
    defer s.mu.RUnlock()
    if value, ok := s.data[string(key)]; ok {
        return value, nil
    }
    return nil, errors.New("value not found")
}