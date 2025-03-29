package main

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/golang-jwt/jwt"
	jwtgo "github.com/golang-jwt/jwt"
	gauth "golang.org/x/oauth2/google"
)

// Config represents the Piano API configuration
type Config struct {
	AID            string
	APIToken       string
	JWTSecret      string
	RestKey        string
	Address        string
	PianoType      string
	Debug          bool
	PrivateKey     string
	TrinityEmptyID string
	CookieDomain   string        // Domain for the cookie
	CookieExpire   time.Duration // Cookie expiration duration
}

// PianoAPI represents the Piano API client
type PianoAPI struct {
	Cfg Config
}

// NewPianoAPI creates a new Piano API client
func NewPianoAPI(cfg Config) *PianoAPI {
	return &PianoAPI{
		Cfg: cfg,
	}
}

// baseRequest makes a base request to the Piano API
func (a *PianoAPI) baseRequest(base string, path string, query url.Values, body []byte) ([]byte, error) {
	query.Add("aid", a.Cfg.AID)
	query.Add("api_token", a.Cfg.APIToken)

	endpoint := fmt.Sprintf("https://%s.piano.io%s%s?%s", a.Cfg.PianoType, base, path, query.Encode())

	responseBody := bytes.NewBuffer(body)
	res, err := http.Post(endpoint, "application/json", responseBody)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	return ioutil.ReadAll(res.Body)
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

// SendResponse sends a JSON response
func SendResponse(w http.ResponseWriter, r *http.Request, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// findUserByEmail finds a user by email in Piano
func findUserByEmail(email string) (string, error) {
	params := url.Values{}
	params.Add("email", email)
	body, err := pianoAPI.V1Request("/publisher/users/get", params, nil)
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
func createPianotoken(pianoID string) string {
	params := url.Values{}
	params.Add("uid", pianoID)
	body, err := pianoAPI.V1Request("/publisher/token", params, nil)
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
	sDec, _ := base64.StdEncoding.DecodeString(pianoAPI.Cfg.JWTSecret)
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
	secr, err := base64.StdEncoding.DecodeString(pianoAPI.Cfg.JWTSecret)
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
func swgStatus(statusReq SWGStatusRequest) error {
	log.Printf("Updating SWG status for user: %s to state: %s", statusReq.Email, statusReq.State)

	// Get pianoID and create token
	pianoID, err := findUserByEmail(statusReq.Email)
	if err != nil {
		return fmt.Errorf("user not found: %v", err)
	}

	userToken := createPianotoken(pianoID)
	if userToken == "" {
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

	// Map product ID to term ID
	termID := "krn_swg1" // Default term ID
	if statusReq.ProductID != "" {
		switch statusReq.ProductID {
		case "SWGPD.1753-5033-6108-05264":
			termID = "TM5ABO7U1ZIL"
		case "SWGPD.0797-0149-8011-19719":
			termID = "TMJT5EVHNL1Q"
		case "SWGPD.4958-2224-9507-43195":
			termID = "TM9CD48918M7"
		case "SWGPD.1775-0797-0744-86052":
			termID = "TM6UZX09QJNK"
		case "SWGPD.4647-7079-7234-14588":
			termID = "TMMVYN314V9T"
		case "SWGPD.1566-8500-5281-95267":
			termID = "TMPOF3VJ8RZC"
		default:
			log.Printf("Unknown product ID: %s, using default term ID", statusReq.ProductID)
		}
	}

	var subscriptionEvent map[string]interface{}
	switch statusReq.State {
	case "SUBSCRIPTION_STARTED":
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
		return fmt.Errorf("failed to prepare event: %v", err)
	}

	params := url.Values{}
	res, err := pianoAPI.V3Request("/publisher/linkedTerm/event", params, payload)
	if err != nil {
		return fmt.Errorf("failed to send event: %v", err)
	}

	log.Printf("Piano API response: %s", string(res))
	return nil
}

// SWGWebhookHandler handles webhooks from Google's SWG
func SWGWebhookHandler(w http.ResponseWriter, r *http.Request) {
	// Read and decode the webhook payload
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		SendResponse(w, r, http.StatusBadRequest, NewHTTPError("Failed to read request body"))
		return
	}

	// Parse the outer message structure
	var msg struct {
		Message struct {
			Data string `json:"data"`
		} `json:"message"`
	}
	if err := json.Unmarshal(body, &msg); err != nil {
		SendResponse(w, r, http.StatusBadRequest, NewHTTPError("Failed to parse message"))
		return
	}

	// Base64 decode the data field
	decodedData, err := base64.StdEncoding.DecodeString(msg.Message.Data)
	if err != nil {
		SendResponse(w, r, http.StatusBadRequest, NewHTTPError("Failed to decode data"))
		return
	}

	// Parse the decoded data into SWGHook
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
			PlanEntitlements []struct {
				Source            string    `json:"source"`
				ProductIds        []string  `json:"productIds"`
				ExpireTime        time.Time `json:"expireTime"`
				SubscriptionToken string    `json:"subscriptionToken"`
			} `json:"planEntitlements"`
			RecurringPlanDetails struct {
				RecurringPlanState string    `json:"recurringPlanState"`
				UpdateTime         time.Time `json:"updateTime"`
				CanceledDetails    struct {
					CancelReason string `json:"cancelReason"`
				} `json:"canceledDetails"`
				RecurrenceTerms struct {
					RecurrencePeriod struct {
						Unit  string `json:"unit"`
						Count int    `json:"count"`
					} `json:"recurrencePeriod"`
					FreeTrialPeriod   struct{} `json:"freeTrialPeriod"`
					GracePeriodMillis string   `json:"gracePeriodMillis"`
				} `json:"recurrenceTerms"`
			} `json:"recurringPlanDetails"`
			PurchaseInfo struct {
				LatestOrderID string `json:"latestOrderId"`
			} `json:"purchaseInfo"`
			ReaderID string `json:"readerId"`
		} `json:"userEntitlementsPlan"`
	}

	if err := json.Unmarshal(decodedData, &inc); err != nil {
		SendResponse(w, r, http.StatusBadRequest, NewHTTPError("Failed to parse webhook data"))
		return
	}

	// Extract productId from subscriptionToken
	var subscriptionToken struct {
		ProductID string `json:"productId"`
	}
	if err := json.Unmarshal([]byte(inc.UserEntitlementsPlan.PlanEntitlements[0].SubscriptionToken), &subscriptionToken); err != nil {
		log.Printf("Error parsing subscription token: %v", err)
		SendResponse(w, r, http.StatusBadRequest, NewHTTPError("Failed to parse subscription token"))
		return
	}

	// Create status request
	statusReq := SWGStatusRequest{
		Email:     inc.UserEntitlementsPlan.ReaderID, // Using ReaderID as email for demo
		State:     inc.EventType,
		Unit:      inc.UserEntitlementsPlan.RecurringPlanDetails.RecurrenceTerms.RecurrencePeriod.Unit,
		Count:     inc.UserEntitlementsPlan.RecurringPlanDetails.RecurrenceTerms.RecurrencePeriod.Count,
		Until:     inc.UserEntitlementsPlan.PlanEntitlements[0].ExpireTime.Unix(),
		ProductID: subscriptionToken.ProductID,
	}

	// Call swgStatus and handle any errors
	if err := swgStatus(statusReq); err != nil {
		SendResponse(w, r, http.StatusInternalServerError, NewHTTPError(err.Error()))
		return
	}

	// Send success response
	SendResponse(w, r, http.StatusOK, map[string]bool{"status": true})
}

// generateRandomPassword generates a random password string
func generateRandomPassword(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes)[:length], nil
}

// createPianoUser creates a new user in Piano
func createPianoUser(email string, password string) (string, error) {
	params := url.Values{}
	params.Add("email", email)
	body, err := pianoAPI.V3Request("/publisher/user/register", params, nil)
	if err != nil {
		return "", err
	}

	type createResult struct {
		Data struct {
			UID string `json:"uid"`
		} `json:"data"`
	}
	cr := createResult{}
	if err := json.Unmarshal(body, &cr); err != nil {
		return "", err
	}

	if password != "" {
		// Set password
		params := url.Values{}
		params.Add("uid", cr.Data.UID)
		params.Add("password", password)
		params.Add("current_password", password)
		_, err := pianoAPI.V1Request("/publisher/password", params, nil)
		if err != nil {
			return "", err
		}
	}

	if cr.Data.UID == "" {
		return "", fmt.Errorf("failed to create user")
	}
	return cr.Data.UID, nil
}

// CreateUserRequest represents the request to create a user
type CreateUserRequest struct {
	ReaderID string `json:"readerId"`
	Partner  string `json:"partner"`
}

// CreateUserResponse represents the response from creating a user
type CreateUserResponse struct {
	Status  string `json:"status"`
	Email   string `json:"email"`
	PianoID string `json:"pianoId"`
}

// createUserHandler handles the creation of a Piano user from an SWG reader ID
func createUserHandler(w http.ResponseWriter, r *http.Request) {
	var req CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendResponse(w, r, http.StatusBadRequest, NewHTTPError("Invalid request body"))
		return
	}

	// Get Google API credentials from environment
	googleAuthJSON := os.Getenv("GOOGLE_AUTH_JSON")
	if googleAuthJSON == "" {
		SendResponse(w, r, http.StatusInternalServerError, NewHTTPError("Google auth configuration missing"))
		return
	}

	// Configure Google API client
	ctx := context.Background()
	conf, err := gauth.JWTConfigFromJSON([]byte(googleAuthJSON), "https://www.googleapis.com/auth/subscribewithgoogle.publications.entitlements.readonly")
	if err != nil {
		SendResponse(w, r, http.StatusInternalServerError, NewHTTPError("Failed to configure Google API"))
		return
	}

	client := conf.Client(ctx)

	// Fetch user email from Google API
	apiURL := fmt.Sprintf("https://subscribewithgoogle.googleapis.com/v1/publications/krone.at/readers/%s", req.ReaderID)
	resp, err := client.Get(apiURL)
	if err != nil {
		SendResponse(w, r, http.StatusInternalServerError, NewHTTPError("Failed to fetch user from Google"))
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		SendResponse(w, r, http.StatusInternalServerError, NewHTTPError("Failed to read Google API response"))
		return
	}

	var reader struct {
		Email string `json:"emailAddress"`
	}
	if err := json.Unmarshal(body, &reader); err != nil {
		SendResponse(w, r, http.StatusInternalServerError, NewHTTPError("Failed to parse Google API response"))
		return
	}

	// Generate random password
	password, err := generateRandomPassword(16)
	if err != nil {
		SendResponse(w, r, http.StatusInternalServerError, NewHTTPError("Failed to generate password"))
		return
	}

	// Create user in Piano
	pianoID, err := createPianoUser(reader.Email, password)
	if err != nil {
		SendResponse(w, r, http.StatusInternalServerError, NewHTTPError("Failed to create Piano user"))
		return
	}

	// Set custom field for SWG reader ID
	fields := map[string]interface{}{
		"swg_reader_id": req.ReaderID,
	}
	cFieldsJSON, _ := json.Marshal(fields)

	params := make(url.Values)
	params.Add("uid", pianoID)
	params.Add("custom_fields", string(cFieldsJSON))
	_, err = pianoAPI.V1Request("/publisher/form", params, nil)
	if err != nil {
		log.Printf("Warning: Failed to set custom field: %v", err)
	}

	// Create Piano token
	token := createPianotoken(pianoID)
	if token == "" {
		SendResponse(w, r, http.StatusInternalServerError, NewHTTPError("Failed to create Piano token"))
		return
	}

	// Set cookie with the token
	http.SetCookie(w, &http.Cookie{
		Name:     "__utp",
		Value:    token,
		Domain:   pianoAPI.Cfg.CookieDomain,
		Expires:  time.Now().Add(pianoAPI.Cfg.CookieExpire),
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})

	SendResponse(w, r, http.StatusOK, CreateUserResponse{
		Status:  "OK",
		Email:   reader.Email,
		PianoID: pianoID,
	})
}

var pianoAPI *PianoAPI

func main() {
	// Parse cookie expiration duration from environment
	cookieExpireStr := os.Getenv("COOKIE_EXPIRE")
	if cookieExpireStr == "" {
		cookieExpireStr = "720h" // Default to 30 days
	}
	cookieExpire, err := time.ParseDuration(cookieExpireStr)
	if err != nil {
		log.Fatalf("Invalid cookie expiration duration: %v", err)
	}

	// Initialize Piano API configuration
	cfg := Config{
		AID:            os.Getenv("PIANO_AID"),
		APIToken:       os.Getenv("PIANO_API_TOKEN"),
		JWTSecret:      os.Getenv("PIANO_JWT_SECRET"),
		RestKey:        os.Getenv("PIANO_REST_KEY"),
		Address:        ":8080",
		PianoType:      os.Getenv("PIANO_TYPE"),
		Debug:          true,
		PrivateKey:     os.Getenv("PIANO_PRIVATE_KEY"),
		TrinityEmptyID: "00000000-0000-0000-0000-000000000000",
		CookieDomain:   os.Getenv("COOKIE_DOMAIN"),
		CookieExpire:   cookieExpire,
	}

	pianoAPI = NewPianoAPI(cfg)

	// Set up routes
	http.HandleFunc("/swg/webhook", SWGWebhookHandler)
	http.HandleFunc("/swg/create-user", createUserHandler)

	// Start server
	server := &http.Server{
		Addr:    cfg.Address,
		Handler: nil,
	}

	// Handle graceful shutdown
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %s\n", err)
		}
	}()

	log.Printf("Server started on %s", cfg.Address)

	<-done
	log.Print("Server stopped")

	// Give the server 5 seconds to finish current requests
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Server shutdown failed: %v", err)
	}
}
