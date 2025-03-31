package piano

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"yourusername/piano-demo/internal/config"
	"yourusername/piano-demo/internal/logger"

	"github.com/golang-jwt/jwt"
	jwtgo "github.com/golang-jwt/jwt"
)

// API represents the Piano API client
type API struct {
	cfg    *config.Config
	logger *logger.Logger
}

// New creates a new Piano API client
func New(cfg *config.Config, logger *logger.Logger) *API {
	return &API{
		cfg:    cfg,
		logger: logger,
	}
}

// baseRequest makes a base request to the Piano API
func (a *API) baseRequest(base string, path string, query url.Values, body []byte) ([]byte, error) {
	query.Add("aid", a.cfg.AID)
	query.Add("api_token", a.cfg.APIToken)

	endpoint := fmt.Sprintf("https://%s.piano.io%s%s?%s", a.cfg.PianoType, base, path, query.Encode())
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
func (a *API) V1Request(path string, query url.Values, body []byte) ([]byte, error) {
	return a.baseRequest("/id/api/v1", path, query, body)
}

// V3Request makes a v3 API request
func (a *API) V3Request(path string, query url.Values, body []byte) ([]byte, error) {
	return a.baseRequest("/api/v3", path, query, body)
}

// FindUserByEmail finds a user by email in Piano
func (a *API) FindUserByEmail(email string) (string, error) {
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

// CreatePianoUser creates a new user in Piano
func (a *API) CreatePianoUser(email string, password string) (string, error) {
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

// CreatePianoToken creates a Piano token for a user
func (a *API) CreatePianoToken(pianoID string) string {
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
	sDec, _ := base64.StdEncoding.DecodeString(a.cfg.JWTSecret)
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
	secr, err := base64.StdEncoding.DecodeString(a.cfg.JWTSecret)
	if err != nil {
		return ""
	}

	tokenString, err := newToken.SignedString([]byte(secr))
	if err != nil {
		return ""
	}

	return tokenString
}

// SetCustomFields sets custom fields for a user
func (a *API) SetCustomFields(pianoID string, fields map[string]interface{}) error {
	cFieldsJSON, err := json.Marshal(fields)
	if err != nil {
		return fmt.Errorf("failed to marshal custom fields: %w", err)
	}

	params := url.Values{}
	params.Add("uid", pianoID)
	params.Add("custom_fields", string(cFieldsJSON))
	_, err = a.V1Request("/publisher/form", params, nil)
	if err != nil {
		return fmt.Errorf("failed to set custom fields: %w", err)
	}
	return nil
}
