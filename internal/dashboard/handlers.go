package dashboard

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/g0lab/g0efilter/internal/logging"
)

/* =========================
   Handlers
   ========================= */

// healthHandler handles health check requests.
func (s *Server) healthHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	err := json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"service": "g0efilter-dashboard",
	})
	if err != nil {
		s.logger.Error("failed to encode health response", "error", err)
	}
}

// ingestHandler processes incoming log events and stores them in the buffer.
//
//nolint:funlen // Function handles complete request processing flow
func (s *Server) ingestHandler(w http.ResponseWriter, r *http.Request) {
	const maxBody = 1 << 20 // 1 MiB

	r.Body = http.MaxBytesReader(w, r.Body, maxBody)

	defer func() { _ = r.Body.Close() }()

	// Read body once into memory
	body, err := io.ReadAll(r.Body)
	if err != nil {
		s.logger.Debug("ingest.read_failed",
			"remote", r.RemoteAddr,
			"error", err.Error(),
		)
		http.Error(w, `{"error":"failed to read body"}`, http.StatusBadRequest)

		return
	}

	s.logger.Log(r.Context(), logging.LevelTrace, "ingest.body_read",
		"remote", r.RemoteAddr,
		"bytes", len(body),
	)

	var payloads []map[string]any

	// Try array first
	err = json.Unmarshal(body, &payloads)
	if err != nil {
		// Try single object
		var obj map[string]any

		err2 := json.Unmarshal(body, &obj)
		if err2 != nil {
			s.logger.Warn("ingest.invalid_json",
				"remote", r.RemoteAddr,
				"error", err2.Error(),
				"body_preview", string(body[:min(len(body), 100)]),
			)
			http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)

			return
		}

		payloads = []map[string]any{obj}
	}

	if len(payloads) == 0 {
		s.logger.Warn("ingest.empty_payload",
			"remote", r.RemoteAddr,
		)
		http.Error(w, `{"error":"empty payload"}`, http.StatusBadRequest)

		return
	}

	s.logger.Debug("ingest.processing",
		"remote", r.RemoteAddr,
		"count", len(payloads),
	)

	results := s.processPayloads(r.Context(), payloads, r.RemoteAddr)

	s.logger.Debug("ingest.completed",
		"remote", r.RemoteAddr,
		"created", len(results),
		"total", len(payloads),
	)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)

	err = json.NewEncoder(w).Encode(map[string]any{
		"created": len(results),
		"results": results,
	})
	if err != nil {
		s.logger.Error("failed to encode ingest response", "error", err)
	}
}

// listLogsHandler handles GET /logs requests and returns filtered log entries as JSON.
func (s *Server) listLogsHandler(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))

	// Sanitize search query to prevent injection
	q = SanitizeSearchQuery(q)

	var sinceID int64

	v := strings.TrimSpace(r.URL.Query().Get("since_id"))
	if v != "" {
		id, err := strconv.ParseInt(v, 10, 64)
		if err == nil && id > 0 {
			sinceID = id
		}
	}

	limit := s.readLimit

	v2 := strings.TrimSpace(r.URL.Query().Get("limit"))
	if v2 != "" {
		n, err := strconv.Atoi(v2)
		if err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}

	s.logger.Debug("logs.query",
		"remote", r.RemoteAddr,
		"query", q,
		"since_id", sinceID,
		"limit", limit,
	)

	rows, err := s.store.Query(r.Context(), q, sinceID, limit)
	if err != nil {
		s.logger.Error("logs.query_failed",
			"error", err.Error(),
			"query", q,
			"since_id", sinceID,
		)
		http.Error(w, "store error", http.StatusInternalServerError)

		return
	}

	s.logger.Debug("logs.query_result",
		"count", len(rows),
	)

	w.Header().Set("Content-Type", "application/json")

	err = json.NewEncoder(w).Encode(rows)
	if err != nil {
		s.logger.Error("failed to encode query response", "error", err)
	}
}

// sseHandler handles Server-Sent Events streaming of log entries to connected clients.
//
//nolint:funlen // SSE handler requires complete event loop implementation
func (s *Server) sseHandler(w http.ResponseWriter, r *http.Request) {
	// SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache, no-transform")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	flusher, ok := w.(http.Flusher)
	if !ok {
		s.logger.Error("sse.flusher_unsupported",
			"remote", r.RemoteAddr,
			"warning", "http.ResponseWriter does not support flushing",
		)
		http.Error(w, "stream unsupported", http.StatusInternalServerError)

		return
	}

	ch := s.broadcaster.Add()
	defer s.broadcaster.Remove(ch)

	s.logger.Debug("sse.client_connected",
		"remote", r.RemoteAddr,
	)

	// Client retry hint
	_, _ = fmt.Fprintf(w, "retry: %d\n\n", int(s.sseRetry.Milliseconds()))
	_, _ = w.Write([]byte(": connected\n\n"))

	flusher.Flush()

	ctx := r.Context()

	hb := time.NewTicker(10 * time.Second)
	defer hb.Stop()

	for {
		select {
		case <-ctx.Done():
			s.logger.Debug("sse.client_disconnected",
				"remote", r.RemoteAddr,
			)

			return
		case msg := <-ch:
			s.logger.Log(ctx, logging.LevelTrace, "sse.send",
				"remote", r.RemoteAddr,
				"bytes", len(msg),
			)
			// Split on newlines per SSE framing
			for len(msg) > 0 {
				i := bytes.IndexByte(msg, '\n')
				if i == -1 {
					_, _ = w.Write([]byte("data: "))
					_, _ = w.Write(msg)
					_, _ = w.Write([]byte("\n\n"))

					break
				}

				_, _ = w.Write([]byte("data: "))
				_, _ = w.Write(msg[:i])
				_, _ = w.Write([]byte("\n"))
				msg = msg[i+1:]
			}

			if len(msg) == 0 {
				_, _ = w.Write([]byte("\n"))
			}

			flusher.Flush()
		case <-hb.C:
			s.logger.Log(ctx, logging.LevelTrace, "sse.heartbeat",
				"remote", r.RemoteAddr,
			)

			_, _ = w.Write([]byte(": ping\n\n"))

			flusher.Flush()
		}
	}
}

// clearLogsHandler handles DELETE /api/v1/logs requests to empty the log buffer.
func (s *Server) clearLogsHandler(w http.ResponseWriter, r *http.Request) {
	s.logger.Debug("logs.clearing",
		"remote", r.RemoteAddr,
	)

	err := s.store.Clear(r.Context())
	if err != nil {
		s.logger.Error("logs.clear_failed",
			"remote", r.RemoteAddr,
			"error", err.Error(),
		)
		http.Error(w, `{"error":"failed to clear logs"}`, http.StatusInternalServerError)

		return
	}

	s.logger.Debug("logs.cleared",
		"remote", r.RemoteAddr,
	)

	s.broadcaster.Send([]byte(`{"type":"cleared"}`))
	w.Header().Set("Content-Type", "application/json")

	err = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	if err != nil {
		s.logger.Error("failed to encode clear response", "error", err)
	}
}

// unblockStatusHandler handles GET /api/v1/unblocks/status requests.
// Returns pending and completed unblocks for UI polling (no API key required).
func (s *Server) unblockStatusHandler(w http.ResponseWriter, _ *http.Request) {
	pending := s.unblockStore.GetPending()
	completed := s.unblockStore.GetCompleted()

	w.Header().Set("Content-Type", "application/json")

	err := json.NewEncoder(w).Encode(map[string]any{
		"pending":   pending,
		"completed": completed,
	})
	if err != nil {
		s.logger.Error("failed to encode unblock status response", "error", err)
	}
}

// listUnblocksHandler handles GET /api/v1/unblocks requests.
// Supports ?hostname= query parameter to filter for a specific host.
func (s *Server) listUnblocksHandler(w http.ResponseWriter, r *http.Request) {
	hostname := strings.TrimSpace(r.URL.Query().Get("hostname"))

	s.logger.Debug("unblocks.list",
		"remote", r.RemoteAddr,
		"hostname", hostname,
	)

	var pending []UnblockRequest
	if hostname != "" {
		pending = s.unblockStore.GetPendingForHost(hostname)
	} else {
		pending = s.unblockStore.GetPending()
	}

	completed := s.unblockStore.GetCompleted()

	w.Header().Set("Content-Type", "application/json")

	err := json.NewEncoder(w).Encode(map[string]any{
		"pending":   pending,
		"completed": completed,
	})
	if err != nil {
		s.logger.Error("failed to encode unblocks response", "error", err)
	}
}

// createUnblockHandler handles POST /api/v1/unblocks requests.
func (s *Server) createUnblockHandler(w http.ResponseWriter, r *http.Request) {
	//nolint:tagliatelle // JSON uses snake_case for API compatibility
	var req struct {
		Type           string `json:"type"`            // "domain" or "ip"
		Value          string `json:"value"`           // the domain or IP to unblock
		TargetHostname string `json:"target_hostname"` // optional: specific host, empty = all
	}

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		s.logger.Debug("unblocks.create.invalid_json",
			"remote", r.RemoteAddr,
			"error", err.Error(),
		)
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)

		return
	}

	// Validate type
	if req.Type != "domain" && req.Type != "ip" {
		s.logger.Debug("unblocks.create.invalid_type",
			"remote", r.RemoteAddr,
			"type", req.Type,
		)
		http.Error(w, `{"error":"type must be 'domain' or 'ip'"}`, http.StatusBadRequest)

		return
	}

	// Validate value
	if strings.TrimSpace(req.Value) == "" {
		s.logger.Debug("unblocks.create.empty_value",
			"remote", r.RemoteAddr,
		)
		http.Error(w, `{"error":"value cannot be empty"}`, http.StatusBadRequest)

		return
	}

	targetHost := strings.TrimSpace(req.TargetHostname)
	id := s.unblockStore.Add(req.Type, strings.TrimSpace(req.Value), targetHost)

	s.logger.Info("unblocks.created",
		"remote", r.RemoteAddr,
		"type", req.Type,
		"value", req.Value,
		"target_hostname", targetHost,
		"id", id,
	)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)

	err = json.NewEncoder(w).Encode(map[string]string{
		"id":     id,
		"status": "pending",
	})
	if err != nil {
		s.logger.Error("failed to encode unblock response", "error", err)
	}
}

// ackUnblockHandler handles POST /api/v1/unblocks/ack requests.
func (s *Server) ackUnblockHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		s.logger.Debug("unblocks.ack.invalid_json",
			"remote", r.RemoteAddr,
			"error", err.Error(),
		)
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)

		return
	}

	if strings.TrimSpace(req.ID) == "" {
		s.logger.Debug("unblocks.ack.empty_id",
			"remote", r.RemoteAddr,
		)
		http.Error(w, `{"error":"id cannot be empty"}`, http.StatusBadRequest)

		return
	}

	ok := s.unblockStore.Acknowledge(strings.TrimSpace(req.ID))
	if !ok {
		s.logger.Debug("unblocks.ack.not_found",
			"remote", r.RemoteAddr,
			"id", req.ID,
		)
		http.Error(w, `{"error":"unblock request not found"}`, http.StatusNotFound)

		return
	}

	s.logger.Info("unblocks.acknowledged",
		"remote", r.RemoteAddr,
		"id", req.ID,
	)

	w.Header().Set("Content-Type", "application/json")

	err = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	if err != nil {
		s.logger.Error("failed to encode ack response", "error", err)
	}
}

// SanitizeSearchQuery validates and sanitizes the search query parameter.
// Returns sanitized query or empty string if validation fails.
func SanitizeSearchQuery(q string) string {
	if q == "" {
		return q
	}

	// Limit query length
	const maxQueryLength = 200
	if len(q) > maxQueryLength {
		return ""
	}

	if !isValidSearchChars(q) {
		return ""
	}

	if hasInjectionPatterns(q) {
		return ""
	}

	return q
}

// isValidSearchChars checks if query contains only valid characters.
func isValidSearchChars(q string) bool {
	for _, r := range q {
		// Reject control characters
		if r < 32 || r == 127 {
			return false
		}
		// Block CRLF injection
		if r == '\n' || r == '\r' || r == '\x00' {
			return false
		}
	}

	return true
}

// hasInjectionPatterns checks for common injection attack patterns.
func hasInjectionPatterns(q string) bool {
	return strings.Contains(q, "\r\n") ||
		strings.Contains(q, "<script") ||
		strings.Contains(q, "javascript:")
}
