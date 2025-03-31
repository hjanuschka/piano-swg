package api

import (
	"encoding/json"
	"log"
	"net/http"
)

// CreateUserRequest represents the request body for user creation
type CreateUserRequest struct {
	ReaderID string `json:"reader_id"`
}

// CreateUserResponse represents the response for user creation
type CreateUserResponse struct {
	Status  string `json:"status"`
	Email   string `json:"email"`
	PianoID string `json:"piano_id"`
}

// DemoData represents the data passed to the demo template
type DemoData struct {
	ButtonText     string
	PaywallTitle   string
	PaywallContent string
	ProductID      string
}

// HTTPError represents an HTTP error response
type HTTPError struct {
	Error string `json:"error"`
}

// NewHTTPError creates a new HTTP error
func NewHTTPError(message string) HTTPError {
	return HTTPError{Error: message}
}

// Response represents a standard API response
type Response struct {
	Status  string      `json:"status"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
	Message string      `json:"message,omitempty"`
}

// NewResponse creates a new response
func NewResponse(status string, data interface{}) Response {
	return Response{
		Status: status,
		Data:   data,
	}
}

// NewErrorResponse creates a new error response
func NewErrorResponse(err error) Response {
	return Response{
		Status: "error",
		Error:  err.Error(),
	}
}

// SendResponse sends a JSON response
func SendResponse(w http.ResponseWriter, r *http.Request, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("Failed to encode response: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}
