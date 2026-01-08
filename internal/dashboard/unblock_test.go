//nolint:testpackage // Testing internal functions
package dashboard

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestUnblockStore_Add(t *testing.T) {
	t.Parallel()

	t.Run("adds new request", func(t *testing.T) {
		t.Parallel()

		store := newUnblockStore()
		id := store.Add("domain", "example.com", "")

		if id == "" {
			t.Error("Add returned empty ID")
		}

		pending := store.GetPending()
		if len(pending) != 1 {
			t.Fatalf("GetPending returned %d items, want 1", len(pending))
		}

		if pending[0].Type != "domain" {
			t.Errorf("Type = %s, want domain", pending[0].Type)
		}

		if pending[0].Value != "example.com" {
			t.Errorf("Value = %s, want example.com", pending[0].Value)
		}
	})

	t.Run("deduplicates same request", func(t *testing.T) {
		t.Parallel()

		store := newUnblockStore()
		id1 := store.Add("domain", "example.com", "host1")
		id2 := store.Add("domain", "example.com", "host1")

		if id1 != id2 {
			t.Errorf("Duplicate request got different IDs: %s vs %s", id1, id2)
		}

		pending := store.GetPending()
		if len(pending) != 1 {
			t.Errorf("GetPending returned %d items, want 1 (deduped)", len(pending))
		}
	})

	t.Run("different targets are not duplicates", func(t *testing.T) {
		t.Parallel()

		store := newUnblockStore()
		store.Add("domain", "example.com", "host1")
		store.Add("domain", "example.com", "host2")
		store.Add("domain", "example.com", "") // all hosts

		pending := store.GetPending()
		if len(pending) != 3 {
			t.Errorf("GetPending returned %d items, want 3", len(pending))
		}
	})
}

func TestUnblockStore_GetPendingForHost(t *testing.T) {
	t.Parallel()

	store := newUnblockStore()
	store.Add("domain", "all-hosts.com", "")       // targets all
	store.Add("domain", "host1-only.com", "host1") // targets host1
	store.Add("domain", "host2-only.com", "host2") // targets host2
	store.Add("ip", "192.168.1.1", "host1")        // targets host1

	t.Run("host1 gets targeted and global requests", func(t *testing.T) {
		t.Parallel()

		pending := store.GetPendingForHost("host1")
		if len(pending) != 3 {
			t.Errorf("host1 got %d requests, want 3", len(pending))
		}

		values := make(map[string]bool)
		for _, req := range pending {
			values[req.Value] = true
		}

		if !values["all-hosts.com"] {
			t.Error("host1 should get all-hosts.com")
		}

		if !values["host1-only.com"] {
			t.Error("host1 should get host1-only.com")
		}

		if !values["192.168.1.1"] {
			t.Error("host1 should get 192.168.1.1")
		}
	})

	t.Run("host2 gets targeted and global requests", func(t *testing.T) {
		t.Parallel()

		pending := store.GetPendingForHost("host2")
		if len(pending) != 2 {
			t.Errorf("host2 got %d requests, want 2", len(pending))
		}
	})

	t.Run("host3 gets only global requests", func(t *testing.T) {
		t.Parallel()

		pending := store.GetPendingForHost("host3")
		if len(pending) != 1 {
			t.Errorf("host3 got %d requests, want 1", len(pending))
		}

		if pending[0].Value != "all-hosts.com" {
			t.Errorf("host3 should only get all-hosts.com, got %s", pending[0].Value)
		}
	})
}

func TestUnblockStore_Acknowledge(t *testing.T) {
	t.Parallel()

	t.Run("acknowledges existing request", func(t *testing.T) {
		t.Parallel()

		store := newUnblockStore()
		id := store.Add("domain", "example.com", "")

		ok := store.Acknowledge(id)
		if !ok {
			t.Error("Acknowledge returned false for existing ID")
		}

		pending := store.GetPending()
		if len(pending) != 0 {
			t.Errorf("After ack, GetPending returned %d items, want 0", len(pending))
		}
	})

	t.Run("returns false for non-existent ID", func(t *testing.T) {
		t.Parallel()

		store := newUnblockStore()
		ok := store.Acknowledge("nonexistent")

		if ok {
			t.Error("Acknowledge returned true for non-existent ID")
		}
	})

	t.Run("double acknowledge returns false", func(t *testing.T) {
		t.Parallel()

		store := newUnblockStore()
		id := store.Add("domain", "example.com", "")

		ok1 := store.Acknowledge(id)
		ok2 := store.Acknowledge(id)

		if !ok1 {
			t.Error("First Acknowledge should return true")
		}

		if ok2 {
			t.Error("Second Acknowledge should return false")
		}
	})
}

//nolint:gocognit,cyclop,funlen // Test function with multiple subtests
func TestUnblockHandlers(t *testing.T) {
	t.Parallel()

	lg := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	newTestServer := func() *Server {
		return &Server{
			logger:       lg,
			store:        newMemStore(100),
			broadcaster:  newBroadcaster(),
			unblockStore: newUnblockStore(),
			apiKey:       "test-key",
			readLimit:    100,
			rateLimiter:  newRateLimiter(50, 100),
			adminLimiter: newRateLimiter(1, 5),
		}
	}

	t.Run("POST /api/v1/unblocks creates request", func(t *testing.T) {
		t.Parallel()

		srv := newTestServer()

		body := `{"type":"domain","value":"example.com","target_hostname":"host1"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/unblocks", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		rec := httptest.NewRecorder()

		srv.createUnblockHandler(rec, req)

		if rec.Code != http.StatusCreated {
			t.Errorf("Status = %d, want %d", rec.Code, http.StatusCreated)
		}

		var resp map[string]string

		err := json.NewDecoder(rec.Body).Decode(&resp)
		if err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		if resp["id"] == "" {
			t.Error("Response missing id")
		}

		if resp["status"] != "pending" {
			t.Errorf("Status = %s, want pending", resp["status"])
		}

		// Verify it's in the store
		pending := srv.unblockStore.GetPending()
		if len(pending) != 1 {
			t.Fatalf("Store has %d items, want 1", len(pending))
		}
	})

	t.Run("POST /api/v1/unblocks rejects invalid type", func(t *testing.T) {
		t.Parallel()

		srv := newTestServer()

		body := `{"type":"invalid","value":"example.com"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/unblocks", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		rec := httptest.NewRecorder()

		srv.createUnblockHandler(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Errorf("Status = %d, want %d", rec.Code, http.StatusBadRequest)
		}
	})

	t.Run("POST /api/v1/unblocks rejects empty value", func(t *testing.T) {
		t.Parallel()

		srv := newTestServer()

		body := `{"type":"domain","value":""}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/unblocks", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		rec := httptest.NewRecorder()

		srv.createUnblockHandler(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Errorf("Status = %d, want %d", rec.Code, http.StatusBadRequest)
		}
	})

	t.Run("GET /api/v1/unblocks returns all pending", func(t *testing.T) {
		t.Parallel()

		srv := newTestServer()
		srv.unblockStore.Add("domain", "example1.com", "")
		srv.unblockStore.Add("ip", "192.168.1.1", "host1")

		req := httptest.NewRequest(http.MethodGet, "/api/v1/unblocks", nil)
		rec := httptest.NewRecorder()

		srv.listUnblocksHandler(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d", rec.Code, http.StatusOK)
		}

		var resp struct {
			Pending []UnblockRequest `json:"pending"`
		}

		err := json.NewDecoder(rec.Body).Decode(&resp)
		if err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		if len(resp.Pending) != 2 {
			t.Errorf("Got %d pending, want 2", len(resp.Pending))
		}
	})

	t.Run("GET /api/v1/unblocks?hostname= filters by host", func(t *testing.T) {
		t.Parallel()

		srv := newTestServer()
		srv.unblockStore.Add("domain", "all-hosts.com", "")       // all
		srv.unblockStore.Add("domain", "host1-only.com", "host1") // host1 only

		req := httptest.NewRequest(http.MethodGet, "/api/v1/unblocks?hostname=host1", nil)
		rec := httptest.NewRecorder()

		srv.listUnblocksHandler(rec, req)

		var resp struct {
			Pending []UnblockRequest `json:"pending"`
		}

		err := json.NewDecoder(rec.Body).Decode(&resp)
		if err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		if len(resp.Pending) != 2 {
			t.Errorf("host1 got %d pending, want 2", len(resp.Pending))
		}

		// Request for host2 should only get the global one
		req2 := httptest.NewRequest(http.MethodGet, "/api/v1/unblocks?hostname=host2", nil)
		rec2 := httptest.NewRecorder()

		srv.listUnblocksHandler(rec2, req2)

		var resp2 struct {
			Pending []UnblockRequest `json:"pending"`
		}

		err2 := json.NewDecoder(rec2.Body).Decode(&resp2)
		if err2 != nil {
			t.Fatalf("Failed to decode response: %v", err2)
		}

		if len(resp2.Pending) != 1 {
			t.Errorf("host2 got %d pending, want 1", len(resp2.Pending))
		}
	})

	t.Run("POST /api/v1/unblocks/ack removes request", func(t *testing.T) {
		t.Parallel()

		srv := newTestServer()
		id := srv.unblockStore.Add("domain", "example.com", "")

		body := `{"id":"` + id + `"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/unblocks/ack", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		rec := httptest.NewRecorder()

		srv.ackUnblockHandler(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d", rec.Code, http.StatusOK)
		}

		pending := srv.unblockStore.GetPending()
		if len(pending) != 0 {
			t.Errorf("After ack, got %d pending, want 0", len(pending))
		}
	})

	t.Run("POST /api/v1/unblocks/ack returns 404 for unknown ID", func(t *testing.T) {
		t.Parallel()

		srv := newTestServer()

		body := `{"id":"nonexistent"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/unblocks/ack", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		rec := httptest.NewRecorder()

		srv.ackUnblockHandler(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Errorf("Status = %d, want %d", rec.Code, http.StatusNotFound)
		}
	})
}

func TestGenerateID(t *testing.T) {
	t.Parallel()

	t.Run("generates unique IDs", func(t *testing.T) {
		t.Parallel()

		ids := make(map[string]bool)

		for i := int64(1); i <= 100; i++ {
			id := generateID(i)
			if ids[id] {
				t.Errorf("Duplicate ID generated: %s", id)
			}

			ids[id] = true
		}
	})

	t.Run("generates 12-character IDs", func(t *testing.T) {
		t.Parallel()

		id := generateID(1)
		if len(id) != 12 {
			t.Errorf("ID length = %d, want 12", len(id))
		}
	})
}
