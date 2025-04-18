package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	t.Run("successful API key extraction", func(t *testing.T) {
		headers := make(http.Header)
		headers.Set("Authorization", "ApiKey my_api_key")

		apiKey, err := GetAPIKey(headers)

		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if apiKey != "my_api_key" {
			t.Errorf("expected apiKey to be 'my_api_key', got '%v'", apiKey)
		}
	})

	t.Run("returns error when authorization header is missing", func(t *testing.T) {
		headers := make(http.Header)

		apiKey, err := GetAPIKey(headers)

		if !errors.Is(err, ErrNoAuthHeaderIncluded) {
			t.Fatalf("expected error '%v', got '%v'", ErrNoAuthHeaderIncluded, err)
		}
		if apiKey != "" {
			t.Errorf("expected apiKey to be empty, got '%v'", apiKey)
		}
	})

	t.Run("returns error for malformed header (missing ApiKey prefix)", func(t *testing.T) {
		headers := make(http.Header)
		headers.Set("Authorization", "Bearer my_api_key")

		apiKey, err := GetAPIKey(headers)

		if err == nil || err.Error() != "malformed authorization header" {
			t.Fatalf("expected error 'malformed authorization header', got '%v'", err)
		}
		if apiKey != "" {
			t.Errorf("expected apiKey to be empty, got '%v'", apiKey)
		}
	})

	t.Run("returns error for malformed header (insufficient parts)", func(t *testing.T) {
		headers := make(http.Header)
		headers.Set("Authorization", "ApiKey")

		apiKey, err := GetAPIKey(headers)

		if err == nil || err.Error() != "malformed authorization header" {
			t.Fatalf("expected error 'malformed authorization header', got '%v'", err)
		}
		if apiKey != "aa" {
			t.Errorf("expected apiKey to be empty, got '%v'", apiKey)
		}
	})
}
