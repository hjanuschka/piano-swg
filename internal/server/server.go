package server

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"yourusername/piano-demo/internal/config"
	"yourusername/piano-demo/internal/logger"
	"yourusername/piano-demo/internal/piano"
	"yourusername/piano-demo/internal/swg"
)

// Server represents the HTTP server
type Server struct {
	cfg      *config.Config
	pianoAPI *piano.API
	swgAPI   *swg.Client
	server   *http.Server
	logger   *logger.Logger
}

// New creates a new HTTP server
func New(cfg *config.Config) (*Server, error) {
	logger := logger.New(cfg.Debug)
	pianoAPI := piano.New(cfg, logger)
	swgAPI, err := swg.New(cfg, logger)
	if err != nil {
		return nil, err
	}

	return &Server{
		cfg:      cfg,
		pianoAPI: pianoAPI,
		swgAPI:   swgAPI,
		logger:   logger,
	}, nil
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

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		s.logger.Error("Failed to read request body: %v", err)
		SendResponse(w, r, http.StatusBadRequest, NewErrorResponse(fmt.Errorf("failed to read request body: %w", err)))
		return
	}

	event, err := swg.ParseWebhookEvent(body)
	if err != nil {
		s.logger.Error("Failed to parse webhook event: %v", err)
		SendResponse(w, r, http.StatusBadRequest, NewErrorResponse(err))
		return
	}

	s.logger.Info("Processing webhook event: %s for reader: %s", event.EventType, event.UserEntitlementsPlan.ReaderID)

	reader, err := s.swgAPI.GetReader(event.UserEntitlementsPlan.ReaderID)
	if err != nil {
		s.logger.Error("Failed to get reader: %v", err)
		SendResponse(w, r, http.StatusInternalServerError, NewErrorResponse(err))
		return
	}

	// Handle the event
	switch event.EventType {
	case "SUBSCRIPTION_STARTED", "SUBSCRIPTION_CANCELED", "SUBSCRIPTION_WAITING_TO_CANCEL", "SUBSCRIPTION_WAITING_TO_RECUR":
		err = s.pianoAPI.swgStatus(SWGStatusRequest{
			Email:     reader.Email,
			State:     event.EventType,
			Unit:      event.UserEntitlementsPlan.PlanType,
			Count:     0,
			Until:     0,
			ProductID: event.UserEntitlementsPlan.PlanEntitlements[0].ProductIds[0],
		})
	default:
		s.logger.Error("Unknown event type: %s", event.EventType)
		err = fmt.Errorf("unknown event type: %s", event.EventType)
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

	reader, err := s.swgAPI.GetReader(req.ReaderID)
	if err != nil {
		s.logger.Error("Failed to get reader: %v", err)
		SendResponse(w, r, http.StatusInternalServerError, NewErrorResponse(err))
		return
	}

	// Generate random password
	password, err := generateRandomPassword(16)
	if err != nil {
		s.logger.Error("Failed to generate password: %v", err)
		SendResponse(w, r, http.StatusInternalServerError, NewErrorResponse(fmt.Errorf("failed to generate password: %w", err)))
		return
	}

	// Check if user already exists
	pianoID, err := s.pianoAPI.FindUserByEmail(reader.Email)
	if err != nil {
		s.logger.Info("Creating new Piano user for email: %s", reader.Email)
		// User doesn't exist, create new user
		pianoID, err = s.pianoAPI.CreatePianoUser(reader.Email, password)
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
	if err := s.pianoAPI.SetCustomFields(pianoID, fields); err != nil {
		s.logger.Error("Failed to set custom field: %v", err)
		s.logger.Debug("Warning: Failed to set custom field: %v", err)
	}

	// Create Piano token
	token := s.pianoAPI.CreatePianoToken(pianoID)
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
