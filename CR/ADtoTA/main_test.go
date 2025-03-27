package main

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Test the mustMarshal function.
func TestMustMarshal(t *testing.T) {
	data := map[string]string{"hello": "world"}
	result := mustMarshal(data)
	if !strings.Contains(result, "hello") {
		t.Errorf("mustMarshal did not produce expected output: %s", result)
	}
}

// Test sendData with a successful HTTP server.
func TestSendDataSuccess(t *testing.T) {
	// Create a test HTTP server that always returns 200 OK.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify header.
		if r.Header.Get("X-ThreatAware-ApiKey") != "test-token" {
			t.Errorf("Expected header X-ThreatAware-ApiKey to be test-token, got %s", r.Header.Get("X-ThreatAware-ApiKey"))
		}
		// Read and verify payload.
		body, _ := ioutil.ReadAll(r.Body)
		var dp DataPacket
		err := json.Unmarshal(body, &dp)
		if err != nil {
			t.Errorf("Failed to unmarshal payload: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	data := []map[string]string{
		{"key": "value"},
	}
	err := sendData(ts.URL, "test-token", "test-tenant", time.Now().UTC().Format("200601021504"), "test-data", 1, data, true)
	if err != nil {
		t.Errorf("sendData returned an error: %v", err)
	}
}

// Test sendData retry logic by simulating failures for the first two attempts and success on the third.
func TestSendDataRetry(t *testing.T) {
	attempts := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			// Simulate failure.
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			// Success on third attempt.
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer ts.Close()

	data := []map[string]string{
		{"key": "value"},
	}
	start := time.Now()
	err := sendData(ts.URL, "test-token", "test-tenant", time.Now().UTC().Format("200601021504"), "test-data", 1, data, true)
	duration := time.Since(start)
	if err != nil {
		t.Errorf("sendData returned an error: %v", err)
	}
	// Check that exactly three attempts were made.
	if attempts != 3 {
		t.Errorf("Expected 3 attempts, got %d", attempts)
	}
	// The total delay should be at least 2s + 4s (first two retry delays).
	if duration < 6*time.Second {
		t.Errorf("Expected duration to be at least 6 seconds due to retries, got %v", duration)
	}
}