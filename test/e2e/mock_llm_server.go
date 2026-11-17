package e2e

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
)

// RecordedRequest stores the raw HTTP method, path, and body received by MockLLMServer.
type RecordedRequest struct {
	Method string
	Path   string
	Body   string
}

// MockLLMServer simulates OpenAI (/v1/chat/completions) and Anthropic (/v1/messages)
// endpoints, supporting both JSON and SSE streaming responses while capturing every
// raw request body received from TraceScrub.
type MockLLMServer struct {
	srv      *httptest.Server
	mu       sync.Mutex
	recorded []RecordedRequest
}

// NewMockLLMServer starts an in-process HTTP mock LLM server.
func NewMockLLMServer() *MockLLMServer {
	m := &MockLLMServer{}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chat/completions", m.handleOpenAI)
	mux.HandleFunc("/v1/messages", m.handleAnthropic)
	mux.HandleFunc("/", m.handleOpenAI)
	m.srv = httptest.NewServer(mux)
	return m
}

// URL returns the base URL of the mock server.
func (m *MockLLMServer) URL() string {
	return m.srv.URL
}

// Close shuts down the mock server.
func (m *MockLLMServer) Close() {
	m.srv.Close()
}

// Reset clears recorded request history.
func (m *MockLLMServer) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.recorded = nil
}

// RecordedRequests returns a snapshot of all requests received by the mock upstream.
func (m *MockLLMServer) RecordedRequests() []RecordedRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]RecordedRequest, len(m.recorded))
	copy(out, m.recorded)
	return out
}

func (m *MockLLMServer) record(r *http.Request, body []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.recorded = append(m.recorded, RecordedRequest{
		Method: r.Method,
		Path:   r.URL.Path,
		Body:   string(body),
	})
}

func (m *MockLLMServer) handleOpenAI(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read failed", http.StatusBadRequest)
		return
	}
	m.record(r, body)

	var req struct {
		Stream   bool `json:"stream"`
		Messages []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
	}
	_ = json.Unmarshal(body, &req)

	echoed := extractAllContent(req.Messages)
	if req.Stream {
		m.writeSplitSSE(w, fmt.Sprintf("data: {\"id\":\"chatcmpl-mock\",\"choices\":[{\"delta\":{\"content\":%s}}]}\n\ndata: [DONE]\n\n", mustJSONString(echoed)))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"id": "chatcmpl-mock",
		"choices": []map[string]any{
			{
				"index": 0,
				"message": map[string]any{
					"role":    "assistant",
					"content": "Echo: " + echoed,
				},
			},
		},
	})
}

func (m *MockLLMServer) handleAnthropic(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read failed", http.StatusBadRequest)
		return
	}
	m.record(r, body)

	var req struct {
		Stream   bool `json:"stream"`
		Messages []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
	}
	_ = json.Unmarshal(body, &req)

	echoed := extractAllContent(req.Messages)
	if req.Stream {
		sse := fmt.Sprintf(
			"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":%s}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
			mustJSONString(echoed),
		)
		m.writeSplitSSE(w, sse)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"id":   "msg-mock",
		"type": "message",
		"content": []map[string]any{
			{
				"type": "text",
				"text": "Echo: " + echoed,
			},
		},
	})
}

// writeSplitSSE writes SSE payloads in small 7-byte chunks so __TS_TOK_<8_hex>__
// placeholders are intentionally split across HTTP chunk boundaries.
func (m *MockLLMServer) writeSplitSSE(w http.ResponseWriter, payload string) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)

	flusher, canFlush := w.(http.Flusher)
	const chunkSize = 7
	for i := 0; i < len(payload); i += chunkSize {
		end := i + chunkSize
		if end > len(payload) {
			end = len(payload)
		}
		_, _ = io.WriteString(w, payload[i:end])
		if canFlush {
			flusher.Flush()
		}
	}
}

func extractAllContent(msgs []struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}) string {
	var parts []string
	for _, m := range msgs {
		parts = append(parts, m.Content)
	}
	return strings.Join(parts, " | ")
}

func mustJSONString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
