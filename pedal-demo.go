package main

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"text/template"
	"time"

	"github.com/caarlos0/env"
	"github.com/fatih/color"
	"github.com/golang-jwt/jwt"
	jwtgo "github.com/golang-jwt/jwt"
	"github.com/joho/godotenv"
	"golang.org/x/oauth2/google"
)

// Logger represents a custom logger with colorized output
type Logger struct {
	infoLogger  *log.Logger
	errorLogger *log.Logger
	debugLogger *log.Logger
	debug       bool
}

// NewLogger creates a new logger instance
func NewLogger(debug bool) *Logger {
	infoColor := color.New(color.FgGreen).SprintFunc()
	errorColor := color.New(color.FgRed).SprintFunc()
	debugColor := color.New(color.FgYellow).SprintFunc()

	return &Logger{
		infoLogger:  log.New(os.Stdout, infoColor("[INFO] "), log.LstdFlags|log.Lshortfile),
		errorLogger: log.New(os.Stderr, errorColor("[ERROR] "), log.LstdFlags|log.Lshortfile),
		debugLogger: log.New(os.Stdout, debugColor("[DEBUG] "), log.LstdFlags|log.Lshortfile),
		debug:       debug,
	}
}

// Info logs an info message
func (l *Logger) Info(format string, v ...interface{}) {
	l.infoLogger.Printf(format, v...)
}

// Error logs an error message
func (l *Logger) Error(format string, v ...interface{}) {
	l.errorLogger.Printf(format, v...)
}

// Debug logs a debug message
func (l *Logger) Debug(format string, v ...interface{}) {
	if l.debug {
		l.debugLogger.Printf(format, v...)
	}
}

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

// generateRandomPassword generates a random password of the specified length
func generateRandomPassword(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
	b := make([]byte, length)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", fmt.Errorf("failed to generate random number: %w", err)
		}
		b[i] = charset[n.Int64()]
	}
	return string(b), nil
}

// Config represents the Piano API configuration
type Config struct {
	AID            string        `env:"PIANO_AID,required"`
	APIToken       string        `env:"PIANO_API_TOKEN,required"`
	JWTSecret      string        `env:"PIANO_JWT_SECRET,required"`
	RestKey        string        `env:"PIANO_REST_KEY,required"`
	Address        string        `env:"SERVER_ADDRESS" envDefault:":8080"`
	PianoType      string        `env:"PIANO_TYPE,required"`
	Debug          bool          `env:"DEBUG" envDefault:"false"`
	PrivateKey     string        `env:"PIANO_PRIVATE_KEY,required"`
	TrinityEmptyID string        `env:"TRINITY_EMPTY_ID" envDefault:"00000000-0000-0000-0000-000000000000"`
	CookieDomain   string        `env:"COOKIE_DOMAIN,required"`
	CookieExpire   time.Duration `env:"COOKIE_EXPIRE" envDefault:"720h"`
	ProductID      string        `env:"PRODUCT_ID" envDefault:"krone.at:showcase"`
	PublicationID  string        `env:"PUBLICATION_ID" envDefault:"krone.at"`
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if c.AID == "" {
		return fmt.Errorf("AID is required")
	}
	if c.APIToken == "" {
		return fmt.Errorf("API token is required")
	}
	if c.JWTSecret == "" {
		return fmt.Errorf("JWT secret is required")
	}
	if c.RestKey == "" {
		return fmt.Errorf("Rest key is required")
	}
	if c.PianoType == "" {
		return fmt.Errorf("Piano type is required")
	}
	if c.PrivateKey == "" {
		return fmt.Errorf("Private key is required")
	}
	if c.CookieDomain == "" {
		return fmt.Errorf("Cookie domain is required")
	}
	if c.PublicationID == "" {
		return fmt.Errorf("Publication ID is required")
	}
	return nil
}

// LoadConfig loads configuration from environment variables
func LoadConfig() (*Config, error) {
	cfg := &Config{}
	if err := env.Parse(cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return cfg, nil
}

// PianoAPI represents the Piano API client
type PianoAPI struct {
	Cfg    Config
	logger *Logger
}

// NewPianoAPI creates a new Piano API client
func NewPianoAPI(cfg Config) *PianoAPI {
	return &PianoAPI{
		Cfg:    cfg,
		logger: NewLogger(cfg.Debug),
	}
}

// baseRequest makes a base request to the Piano API
func (a *PianoAPI) baseRequest(base string, path string, query url.Values, body []byte) ([]byte, error) {
	query.Add("aid", a.Cfg.AID)
	query.Add("api_token", a.Cfg.APIToken)

	endpoint := fmt.Sprintf("https://%s.piano.io%s%s?%s", a.Cfg.PianoType, base, path, query.Encode())
	a.logger.Debug("Making request to: %s", endpoint)

	responseBody := bytes.NewBuffer(body)
	res, err := http.Post(endpoint, "application/json", responseBody)
	if err != nil {
		a.logger.Error("Failed to make request: %v", err)
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer res.Body.Close()

	respBody, err := ioutil.ReadAll(res.Body)
	if err != nil {
		a.logger.Error("Failed to read response body: %v", err)
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if res.StatusCode != http.StatusOK {
		a.logger.Error("Unexpected status code: %d, body: %s", res.StatusCode, string(respBody))
		return nil, fmt.Errorf("unexpected status code: %d, body: %s", res.StatusCode, string(respBody))
	}

	a.logger.Debug("Response received: %s", string(respBody))
	return respBody, nil
}

// V1Request makes a v1 API request
func (a *PianoAPI) V1Request(path string, query url.Values, body []byte) ([]byte, error) {
	return a.baseRequest("/id/api/v1", path, query, body)
}

// V3Request makes a v3 API request
func (a *PianoAPI) V3Request(path string, query url.Values, body []byte) ([]byte, error) {
	return a.baseRequest("/api/v3", path, query, body)
}

// SWGStatusRequest represents the SWG status request
type SWGStatusRequest struct {
	Email     string `json:"email"`
	State     string `json:"state"`
	Unit      string `json:"unit"`
	Count     int    `json:"count"`
	Until     int64  `json:"until"`
	ProductID string `json:"productId"`
}

// SWGStatusResponse represents the SWG status response
type SWGStatusResponse struct {
	Status string `json:"status"`
}

// HTTPError represents an HTTP error response
type HTTPError struct {
	Error string `json:"error"`
}

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

// findUserByEmail finds a user by email in Piano
func (a *PianoAPI) findUserByEmail(email string) (string, error) {
	params := url.Values{}
	params.Add("email", email)
	body, err := a.V1Request("/publisher/users/get", params, nil)
	if err != nil {
		return "", err
	}

	var result struct {
		UID string `json:"UID"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}

	if result.UID == "" {
		return "", fmt.Errorf("user not found")
	}

	return result.UID, nil
}

// createPianotoken creates a Piano token for a user
func (a *PianoAPI) createPianotoken(pianoID string) string {
	params := url.Values{}
	params.Add("uid", pianoID)
	body, err := a.V1Request("/publisher/token", params, nil)
	if err != nil {
		return ""
	}

	var result struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return ""
	}

	// Unpack and modify token
	sDec, _ := base64.StdEncoding.DecodeString(a.Cfg.JWTSecret)
	token, err := jwt.Parse(result.AccessToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return sDec, nil
	})
	if err != nil {
		return ""
	}

	claims := token.Claims.(jwt.MapClaims)
	claims["r"] = true

	// Re-sign token
	newToken := jwtgo.NewWithClaims(jwtgo.SigningMethodHS256, claims)
	secr, err := base64.StdEncoding.DecodeString(a.Cfg.JWTSecret)
	if err != nil {
		return ""
	}

	tokenString, err := newToken.SignedString([]byte(secr))
	if err != nil {
		return ""
	}

	return tokenString
}

// formatPeriod formats the subscription period
func formatPeriod(count int, unit string) string {
	if count == 0 {
		return unit
	}
	return fmt.Sprintf("%d %s", count, unit)
}

// swgStatus handles SWG status updates
func (a *PianoAPI) swgStatus(statusReq SWGStatusRequest) error {
	a.logger.Info("Updating SWG status for user: %s to state: %s", statusReq.Email, statusReq.State)

	// Get pianoID and create token
	pianoID, err := a.findUserByEmail(statusReq.Email)
	if err != nil {
		a.logger.Error("User not found: %v", err)
		return fmt.Errorf("user not found: %v", err)
	}

	userToken := a.createPianotoken(pianoID)
	if userToken == "" {
		a.logger.Error("Failed to create token")
		return fmt.Errorf("failed to create token")
	}

	// Create hashed IDs from email
	hasher := md5.New()
	hasher.Write([]byte(statusReq.Email))
	emailHash := hex.EncodeToString(hasher.Sum(nil))

	unit := "month"
	count := 1

	if statusReq.Unit == "MONTHLY" {
		unit = "month"
		count = statusReq.Count
	} else if statusReq.Unit == "YEARLY" {
		unit = "annual"
		count = 0
	} else if statusReq.Unit == "QUARTERLY" {
		unit = "quarter"
		count = statusReq.Count
	} else if statusReq.Unit == "HALFYEARLY" {
		unit = "bi-annual"
		count = 0
	}

	termID := statusReq.ProductID
	a.logger.Debug("Using term ID: %s", termID)

	var subscriptionEvent map[string]interface{}
	switch statusReq.State {
	case "SUBSCRIPTION_STARTED":
		a.logger.Info("Creating new subscription for user: %s", statusReq.Email)
		subscriptionEvent = map[string]interface{}{
			"action": "subscription_create",
			"subscription": map[string]interface{}{
				"subscription_id":  fmt.Sprintf("SUB%s-%s", emailHash, statusReq.ProductID),
				"user_token":       userToken,
				"external_term_id": termID,
				"state":            "active",
				"valid_to":         statusReq.Until,
				"auto_renew":       true,
				"purchase": map[string]interface{}{
					"trial": "No",
				},
				"period":             formatPeriod(count, unit),
				"access_custom_data": "{}",
			},
			"conversion": map[string]interface{}{
				"conversion_id": fmt.Sprintf("CONV%s_%d", emailHash, time.Now().Unix()),
				"create_date":   time.Now().Unix(),
			},
		}
	case "SUBSCRIPTION_CANCELED":
		a.logger.Info("Terminating subscription for user: %s", statusReq.Email)
		subscriptionEvent = map[string]interface{}{
			"action": "subscription_terminate",
			"subscription": map[string]interface{}{
				"subscription_id":  fmt.Sprintf("SUB%s-%s", emailHash, statusReq.ProductID),
				"user_token":       userToken,
				"external_term_id": termID,
				"state":            "active",
				"valid_to":         statusReq.Until,
				"auto_renew":       true,
				"purchase": map[string]interface{}{
					"trial": "No",
				},
				"period":             formatPeriod(count, unit),
				"access_custom_data": "{}",
			},
		}
	case "SUBSCRIPTION_WAITING_TO_CANCEL":
		a.logger.Info("Updating subscription (waiting to cancel) for user: %s", statusReq.Email)
		subscriptionEvent = map[string]interface{}{
			"action": "subscription_update",
			"subscription": map[string]interface{}{
				"subscription_id":  fmt.Sprintf("SUB%s-%s", emailHash, statusReq.ProductID),
				"user_token":       userToken,
				"external_term_id": termID,
				"state":            "active",
				"valid_to":         statusReq.Until,
				"auto_renew":       true,
				"purchase": map[string]interface{}{
					"trial": "No",
				},
				"period":             formatPeriod(count, unit),
				"access_custom_data": "{}",
			},
		}
	case "SUBSCRIPTION_WAITING_TO_RECUR":
		a.logger.Info("Renewing subscription for user: %s", statusReq.Email)
		subscriptionEvent = map[string]interface{}{
			"action": "subscription_renew",
			"subscription": map[string]interface{}{
				"subscription_id":  fmt.Sprintf("SUB%s-%s", emailHash, statusReq.ProductID),
				"user_token":       userToken,
				"external_term_id": termID,
				"state":            "active",
				"valid_to":         statusReq.Until,
				"auto_renew":       true,
				"purchase": map[string]interface{}{
					"trial": "No",
				},
				"period":             formatPeriod(count, unit),
				"access_custom_data": "{}",
			},
			"conversion": map[string]interface{}{
				"conversion_id": fmt.Sprintf("CONV%s_%d", emailHash, time.Now().Unix()),
				"create_date":   time.Now().Unix(),
			},
		}
	}

	payload, err := json.Marshal(subscriptionEvent)
	if err != nil {
		a.logger.Error("Failed to prepare event: %v", err)
		return fmt.Errorf("failed to prepare event: %v", err)
	}

	params := url.Values{}
	res, err := a.V3Request("/publisher/linkedTerm/event", params, payload)
	if err != nil {
		a.logger.Error("Failed to send event: %v", err)
		return fmt.Errorf("failed to send event: %v", err)
	}

	a.logger.Info("Successfully processed subscription event for user: %s", statusReq.Email)
	a.logger.Debug("Piano API response: %s", string(res))
	return nil
}

// Server represents the HTTP server
type Server struct {
	cfg      *Config
	pianoAPI *PianoAPI
	server   *http.Server
	logger   *Logger
}

// NewServer creates a new HTTP server
func NewServer(cfg *Config, pianoAPI *PianoAPI) *Server {
	return &Server{
		cfg:      cfg,
		pianoAPI: pianoAPI,
		logger:   NewLogger(cfg.Debug),
	}
}

// Start starts the HTTP server
func (s *Server) Start() error {
	mux := http.NewServeMux()

	// Register routes
	mux.HandleFunc("/swg/webhook", s.handleWebhook)
	mux.HandleFunc("/swg/create-user", s.handleCreateUser)
	mux.HandleFunc("/demo", s.handleDemo)

	// Serve static files
	fs := http.FileServer(http.Dir("static"))
	mux.Handle("/static/", http.StripPrefix("/static/", fs))

	// Create server with timeouts
	s.server = &http.Server{
		Addr:         s.cfg.Address,
		Handler:      Chain(mux, LoggingMiddleware, RecoveryMiddleware),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Handle graceful shutdown
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		s.logger.Info("Server starting on %s", s.cfg.Address)
		if err := s.server.ListenAndServeTLS("certs/server.crt", "certs/server.key"); err != nil && err != http.ErrServerClosed {
			s.logger.Error("Server failed: %v", err)
			log.Fatalf("listen: %s\n", err)
		}
	}()

	s.logger.Info("Server started on %s", s.cfg.Address)
	s.logger.Info("Piano AID: %s", s.cfg.AID)
	<-done
	s.logger.Info("Server stopped")

	// Give the server 5 seconds to finish current requests
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.server.Shutdown(ctx)
}

// handleWebhook handles webhook requests
func (s *Server) handleWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.logger.Error("Method not allowed: %s", r.Method)
		SendResponse(w, r, http.StatusMethodNotAllowed, NewErrorResponse(fmt.Errorf("method not allowed")))
		return
	}

	// Read and decode the webhook payload
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		s.logger.Error("Failed to read request body: %v", err)
		SendResponse(w, r, http.StatusBadRequest, NewErrorResponse(fmt.Errorf("failed to read request body: %w", err)))
		return
	}

	// Parse the outer message structure
	var msg struct {
		Message struct {
			Data string `json:"data"`
		} `json:"message"`
	}
	if err := json.Unmarshal(body, &msg); err != nil {
		s.logger.Error("Failed to parse message: %v", err)
		SendResponse(w, r, http.StatusBadRequest, NewErrorResponse(fmt.Errorf("failed to parse message: %w", err)))
		return
	}

	// Base64 decode the data field
	decodedData, err := base64.StdEncoding.DecodeString(msg.Message.Data)
	if err != nil {
		s.logger.Error("Failed to decode data: %v", err)
		SendResponse(w, r, http.StatusBadRequest, NewErrorResponse(fmt.Errorf("failed to decode data: %w", err)))
		return
	}

	s.logger.Debug("Received webhook data: %s", string(decodedData))

	// Parse the decoded data
	var inc struct {
		ID                   string    `json:"id"`
		CreateTime           time.Time `json:"createTime"`
		EventType            string    `json:"eventType"`
		EventObjectType      string    `json:"eventObjectType"`
		UserEntitlementsPlan struct {
			Name             string `json:"name"`
			PublicationID    string `json:"publicationId"`
			PlanType         string `json:"planType"`
			PlanID           string `json:"planId"`
			ReaderID         string `json:"readerId"`
			PlanEntitlements []struct {
				Source            string   `json:"source"`
				ProductIds        []string `json:"productIds"`
				ExpireTime        string   `json:"expireTime"`
				SubscriptionToken string   `json:"subscriptionToken"`
			} `json:"planEntitlements"`
		} `json:"userEntitlementsPlan"`
	}

	if err := json.Unmarshal(decodedData, &inc); err != nil {
		s.logger.Error("Failed to parse webhook data: %v", err)
		SendResponse(w, r, http.StatusBadRequest, NewErrorResponse(fmt.Errorf("failed to parse webhook data: %w", err)))
		return
	}

	s.logger.Info("Processing webhook event: %s for reader: %s", inc.EventType, inc.UserEntitlementsPlan.ReaderID)

	// Get Google API credentials from environment
	googleAuthJSON := os.Getenv("GOOGLE_AUTH_JSON")
	if googleAuthJSON == "" {
		s.logger.Error("Google auth configuration missing")
		SendResponse(w, r, http.StatusInternalServerError, NewErrorResponse(fmt.Errorf("Google auth configuration missing")))
		return
	}

	// Configure Google API client
	ctx := context.Background()
	conf, err := google.JWTConfigFromJSON([]byte(googleAuthJSON), "https://www.googleapis.com/auth/subscribewithgoogle.publications.entitlements.readonly")
	if err != nil {
		s.logger.Error("Failed to configure Google API: %v", err)
		SendResponse(w, r, http.StatusInternalServerError, NewErrorResponse(fmt.Errorf("failed to configure Google API: %w", err)))
		return
	}

	client := conf.Client(ctx)

	// Fetch user email from Google API using the reader ID
	apiURL := fmt.Sprintf("https://subscribewithgoogle.googleapis.com/v1/publications/%s/readers/%s", s.cfg.PublicationID, inc.UserEntitlementsPlan.ReaderID)
	s.logger.Debug("Fetching user from Google API: %s", apiURL)
	resp, err := client.Get(apiURL)
	if err != nil {
		s.logger.Error("Failed to fetch user from Google: %v", err)
		SendResponse(w, r, http.StatusInternalServerError, NewErrorResponse(fmt.Errorf("failed to fetch user from Google: %w", err)))
		return
	}
	defer resp.Body.Close()

	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		s.logger.Error("Failed to read Google API response: %v", err)
		SendResponse(w, r, http.StatusInternalServerError, NewErrorResponse(fmt.Errorf("failed to read Google API response: %w", err)))
		return
	}

	var reader struct {
		Email string `json:"emailAddress"`
	}
	if err := json.Unmarshal(body, &reader); err != nil {
		s.logger.Error("Failed to parse Google API response: %v", err)
		SendResponse(w, r, http.StatusInternalServerError, NewErrorResponse(fmt.Errorf("failed to parse Google API response: %w", err)))
		return
	}

	s.logger.Debug("Retrieved user email: %s", reader.Email)

	// Parse the subscription token to get the product ID
	var subscriptionToken struct {
		ProductID string `json:"productId"`
	}
	if len(inc.UserEntitlementsPlan.PlanEntitlements) > 0 {
		if err := json.Unmarshal([]byte(inc.UserEntitlementsPlan.PlanEntitlements[0].SubscriptionToken), &subscriptionToken); err != nil {
			s.logger.Error("Failed to parse subscription token: %v", err)
			SendResponse(w, r, http.StatusInternalServerError, NewErrorResponse(fmt.Errorf("failed to parse subscription token: %w", err)))
			return
		}
	}

	s.logger.Debug("Using product ID: %s", subscriptionToken.ProductID)

	// Handle the event
	switch inc.EventType {
	case "SUBSCRIPTION_STARTED", "SUBSCRIPTION_CANCELED", "SUBSCRIPTION_WAITING_TO_CANCEL", "SUBSCRIPTION_WAITING_TO_RECUR":
		err = s.pianoAPI.swgStatus(SWGStatusRequest{
			Email:     reader.Email,
			State:     inc.EventType,
			Unit:      inc.UserEntitlementsPlan.PlanType,
			Count:     0,
			Until:     0,
			ProductID: subscriptionToken.ProductID,
		})
	default:
		s.logger.Error("Unknown event type: %s", inc.EventType)
		err = fmt.Errorf("unknown event type: %s", inc.EventType)
	}

	if err != nil {
		s.logger.Error("Failed to process webhook: %v", err)
		SendResponse(w, r, http.StatusInternalServerError, NewErrorResponse(err))
		return
	}

	s.logger.Info("Successfully processed webhook for user: %s", reader.Email)
	SendResponse(w, r, http.StatusOK, NewResponse("success", nil))
}

// handleCreateUser handles user creation requests
func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.logger.Error("Method not allowed: %s", r.Method)
		SendResponse(w, r, http.StatusMethodNotAllowed, NewErrorResponse(fmt.Errorf("method not allowed")))
		return
	}

	var req CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.logger.Error("Invalid request body: %v", err)
		SendResponse(w, r, http.StatusBadRequest, NewErrorResponse(fmt.Errorf("invalid request body: %w", err)))
		return
	}

	s.logger.Info("Creating user for reader ID: %s", req.ReaderID)

	// Get Google API credentials from environment
	googleAuthJSON := os.Getenv("GOOGLE_AUTH_JSON")
	if googleAuthJSON == "" {
		s.logger.Error("Google auth configuration missing")
		SendResponse(w, r, http.StatusInternalServerError, NewErrorResponse(fmt.Errorf("Google auth configuration missing")))
		return
	}

	// Configure Google API client
	ctx := context.Background()
	conf, err := google.JWTConfigFromJSON([]byte(googleAuthJSON), "https://www.googleapis.com/auth/subscribewithgoogle.publications.entitlements.readonly")
	if err != nil {
		s.logger.Error("Failed to configure Google API: %v", err)
		SendResponse(w, r, http.StatusInternalServerError, NewErrorResponse(fmt.Errorf("failed to configure Google API: %w", err)))
		return
	}

	client := conf.Client(ctx)

	// Fetch user email from Google API
	apiURL := fmt.Sprintf("https://subscribewithgoogle.googleapis.com/v1/publications/%s/readers/%s", s.cfg.PublicationID, req.ReaderID)
	s.logger.Debug("Fetching user from Google API: %s", apiURL)
	resp, err := client.Get(apiURL)
	if err != nil {
		s.logger.Error("Failed to fetch user from Google: %v", err)
		SendResponse(w, r, http.StatusInternalServerError, NewErrorResponse(fmt.Errorf("failed to fetch user from Google: %w", err)))
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		s.logger.Error("Failed to read Google API response: %v", err)
		SendResponse(w, r, http.StatusInternalServerError, NewErrorResponse(fmt.Errorf("failed to read Google API response: %w", err)))
		return
	}

	var reader struct {
		Email string `json:"emailAddress"`
	}
	if err := json.Unmarshal(body, &reader); err != nil {
		s.logger.Error("Failed to parse Google API response: %v", err)
		SendResponse(w, r, http.StatusInternalServerError, NewErrorResponse(fmt.Errorf("failed to parse Google API response: %w", err)))
		return
	}

	s.logger.Debug("Retrieved user email: %s", reader.Email)

	// Generate random password
	password, err := generateRandomPassword(16)
	if err != nil {
		s.logger.Error("Failed to generate password: %v", err)
		SendResponse(w, r, http.StatusInternalServerError, NewErrorResponse(fmt.Errorf("failed to generate password: %w", err)))
		return
	}

	// Check if user already exists
	pianoID, err := s.pianoAPI.findUserByEmail(reader.Email)
	if err != nil {
		s.logger.Info("Creating new Piano user for email: %s", reader.Email)
		// User doesn't exist, create new user
		pianoID, err = s.pianoAPI.createPianoUser(reader.Email, password)
		if err != nil {
			s.logger.Error("Failed to create Piano user: %v", err)
			SendResponse(w, r, http.StatusInternalServerError, NewErrorResponse(fmt.Errorf("failed to create Piano user: %w", err)))
			return
		}
		s.logger.Info("Created new Piano user with ID: %s", pianoID)
	} else {
		s.logger.Info("Found existing Piano user with ID: %s", pianoID)
	}

	// Set custom field for SWG reader ID
	fields := map[string]interface{}{
		"swg_reader_id": req.ReaderID,
	}
	cFieldsJSON, _ := json.Marshal(fields)

	params := url.Values{}
	params.Add("uid", pianoID)
	params.Add("custom_fields", string(cFieldsJSON))
	_, err = s.pianoAPI.V1Request("/publisher/form", params, nil)
	if err != nil {
		s.logger.Error("Failed to set custom field: %v", err)
		s.pianoAPI.logger.Debug("Warning: Failed to set custom field: %v", err)
	}

	// Create Piano token
	token := s.pianoAPI.createPianotoken(pianoID)
	if token == "" {
		s.logger.Error("Failed to create Piano token")
		SendResponse(w, r, http.StatusInternalServerError, NewErrorResponse(fmt.Errorf("failed to create Piano token")))
		return
	}

	// Set cookie with the token
	http.SetCookie(w, &http.Cookie{
		Name:     "__utp",
		Value:    token,
		Domain:   s.cfg.CookieDomain,
		Expires:  time.Now().Add(s.cfg.CookieExpire),
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})

	s.logger.Info("Successfully created/updated user for email: %s", reader.Email)
	SendResponse(w, r, http.StatusOK, NewResponse("success", CreateUserResponse{
		Status:  "OK",
		Email:   reader.Email,
		PianoID: pianoID,
	}))
}

// DemoData represents the data passed to the demo template
type DemoData struct {
	ButtonText     string
	PaywallTitle   string
	PaywallContent string
	ProductID      string
}

// handleDemo serves the demo page with SwG integration
func (s *Server) handleDemo(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("static/templates/demo.html")
	if err != nil {
		log.Printf("Error parsing template: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	data := DemoData{
		ButtonText:     "Subscribe with Google",
		PaywallTitle:   "Premium Article",
		PaywallContent: "This article is only available to subscribers. Get access to all premium articles and exclusive content from Krone.",
		ProductID:      s.cfg.ProductID,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("Error executing template: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

// Middleware represents a function that wraps an http.Handler
type Middleware func(http.Handler) http.Handler

// Chain applies middlewares to a handler
func Chain(h http.Handler, middlewares ...Middleware) http.Handler {
	for i := len(middlewares) - 1; i >= 0; i-- {
		h = middlewares[i](h)
	}
	return h
}

// LoggingMiddleware logs all requests
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s %v", r.Method, r.RequestURI, r.RemoteAddr, time.Since(start))
	})
}

// RecoveryMiddleware recovers from panics
func RecoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("panic: %v", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// createPianoUser creates a new user in Piano
func (a *PianoAPI) createPianoUser(email string, password string) (string, error) {
	params := url.Values{}
	params.Add("email", email)
	body, err := a.V3Request("/publisher/user/register", params, nil)
	if err != nil {
		return "", fmt.Errorf("failed to register user: %w", err)
	}

	type createResult struct {
		Data struct {
			UID string `json:"uid"`
		} `json:"data"`
	}
	cr := createResult{}
	if err := json.Unmarshal(body, &cr); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	if password != "" {
		// Set password
		params := url.Values{}
		params.Add("uid", cr.Data.UID)
		params.Add("password", password)
		params.Add("current_password", password)
		_, err := a.V1Request("/publisher/password", params, nil)
		if err != nil {
			return "", fmt.Errorf("failed to set password: %w", err)
		}
	}

	if cr.Data.UID == "" {
		return "", fmt.Errorf("failed to create user: no UID returned")
	}
	return cr.Data.UID, nil
}

func main() {
	// Parse command line flags
	debug := flag.Bool("debug", false, "Enable debug mode")
	flag.Parse()

	// Load .env file
	envPath := filepath.Join(".env")
	if err := godotenv.Load(envPath); err != nil {
		log.Printf("Warning: Failed to load .env file: %v", err)
		log.Println("Using environment variables directly")
	}

	// Load configuration
	cfg, err := LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Override debug setting from command line
	cfg.Debug = *debug

	// Create PianoAPI client
	pianoAPI := NewPianoAPI(*cfg)

	// Create and start server
	server := NewServer(cfg, pianoAPI)
	if err := server.Start(); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
