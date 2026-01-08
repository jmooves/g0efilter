package dashboard

import (
	"sync"
	"time"
)

// UnblockRequest represents a pending unblock request.
//
//nolint:tagliatelle // JSON uses snake_case for API compatibility
type UnblockRequest struct {
	ID             string    `json:"id"`
	Type           string    `json:"type"` // "domain" or "ip"
	Value          string    `json:"value"`
	TargetHostname string    `json:"target_hostname"` // empty means "all"
	CreatedAt      time.Time `json:"created_at"`
}

// CompletedUnblock represents an acknowledged (completed) unblock.
//
//nolint:tagliatelle // JSON uses snake_case for API compatibility
type CompletedUnblock struct {
	Type        string    `json:"type"`
	Value       string    `json:"value"`
	CompletedAt time.Time `json:"completed_at"`
}

// UnblockStore manages pending unblock requests with thread-safe operations.
type UnblockStore interface {
	// Add queues a new unblock request and returns its ID.
	Add(reqType, value, targetHostname string) string
	// GetPending returns all pending unblock requests.
	GetPending() []UnblockRequest
	// GetPendingForHost returns pending requests for a specific hostname (or all if hostname matches).
	GetPendingForHost(hostname string) []UnblockRequest
	// Acknowledge marks a request as processed and moves it to completed.
	Acknowledge(id string) bool
	// GetCompleted returns all completed unblocks.
	GetCompleted() []CompletedUnblock
}

// memUnblockStore is an in-memory implementation of UnblockStore.
type memUnblockStore struct {
	mu        sync.RWMutex
	requests  map[string]UnblockRequest
	completed []CompletedUnblock
	counter   int64
}

// newUnblockStore creates a new in-memory unblock store.
func newUnblockStore() *memUnblockStore {
	return &memUnblockStore{
		requests:  make(map[string]UnblockRequest),
		completed: make([]CompletedUnblock, 0),
	}
}

// Add queues a new unblock request and returns its ID.
func (s *memUnblockStore) Add(reqType, value, targetHostname string) string {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check for duplicate pending requests (same type, value, and target)
	for _, req := range s.requests {
		if req.Type == reqType && req.Value == value && req.TargetHostname == targetHostname {
			return req.ID // Return existing request ID
		}
	}

	s.counter++
	id := generateID(s.counter)

	s.requests[id] = UnblockRequest{
		ID:             id,
		Type:           reqType,
		Value:          value,
		TargetHostname: targetHostname,
		CreatedAt:      time.Now().UTC(),
	}

	return id
}

// GetPending returns all pending unblock requests.
func (s *memUnblockStore) GetPending() []UnblockRequest {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]UnblockRequest, 0, len(s.requests))
	for _, req := range s.requests {
		result = append(result, req)
	}

	return result
}

// GetPendingForHost returns pending requests matching a specific hostname.
// Returns requests where TargetHostname is empty (all hosts) or matches the given hostname.
func (s *memUnblockStore) GetPendingForHost(hostname string) []UnblockRequest {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]UnblockRequest, 0, len(s.requests))
	for _, req := range s.requests {
		// Match if target is empty (all hosts) or matches specific hostname
		if req.TargetHostname == "" || req.TargetHostname == hostname {
			result = append(result, req)
		}
	}

	return result
}

// Acknowledge marks a request as processed and moves it to completed.
func (s *memUnblockStore) Acknowledge(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, exists := s.requests[id]
	if exists {
		// Move to completed list
		s.completed = append(s.completed, CompletedUnblock{
			Type:        req.Type,
			Value:       req.Value,
			CompletedAt: time.Now().UTC(),
		})
		delete(s.requests, id)

		// Keep completed list bounded (last 100 entries)
		const maxCompleted = 100
		if len(s.completed) > maxCompleted {
			s.completed = s.completed[len(s.completed)-maxCompleted:]
		}

		return true
	}

	return false
}

// GetCompleted returns all completed unblocks.
func (s *memUnblockStore) GetCompleted() []CompletedUnblock {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]CompletedUnblock, len(s.completed))
	copy(result, s.completed)

	return result
}

// generateID creates a unique ID for an unblock request.
func generateID(counter int64) string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"

	timestamp := time.Now().UnixNano()

	// Simple ID: base36-ish encoding of timestamp + counter
	combined := timestamp + counter
	id := make([]byte, 12)

	for i := range id {
		id[i] = chars[combined%int64(len(chars))]
		combined /= int64(len(chars))
	}

	return string(id)
}
