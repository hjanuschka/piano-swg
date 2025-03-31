package swg

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"yourusername/piano-demo/internal/config"
	"yourusername/piano-demo/internal/logger"

	"golang.org/x/oauth2/google"
)

// Client represents the SwG API client
type Client struct {
	cfg    *config.Config
	logger *logger.Logger
	client *http.Client
}

// New creates a new SwG API client
func New(cfg *config.Config, logger *logger.Logger) (*Client, error) {
	ctx := context.Background()
	conf, err := google.JWTConfigFromJSON([]byte(cfg.GoogleAuthJSON), "https://www.googleapis.com/auth/subscribewithgoogle.publications.entitlements.readonly")
	if err != nil {
		return nil, fmt.Errorf("failed to configure Google API: %w", err)
	}

	return &Client{
		cfg:    cfg,
		logger: logger,
		client: conf.Client(ctx),
	}, nil
}

// Reader represents a SwG reader
type Reader struct {
	Email string `json:"emailAddress"`
}

// GetReader fetches a reader's information from the SwG API
func (c *Client) GetReader(readerID string) (*Reader, error) {
	apiURL := fmt.Sprintf("https://subscribewithgoogle.googleapis.com/v1/publications/%s/readers/%s", c.cfg.PublicationID, readerID)
	c.logger.Debug("Fetching user from Google API: %s", apiURL)

	resp, err := c.client.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch user from Google: %w", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read Google API response: %w", err)
	}

	var reader Reader
	if err := json.Unmarshal(body, &reader); err != nil {
		return nil, fmt.Errorf("failed to parse Google API response: %w", err)
	}

	c.logger.Debug("Retrieved user email: %s", reader.Email)
	return &reader, nil
}

// WebhookEvent represents a SwG webhook event
type WebhookEvent struct {
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

// ParseWebhookEvent parses a webhook event from the request body
func ParseWebhookEvent(body []byte) (*WebhookEvent, error) {
	var msg struct {
		Message struct {
			Data string `json:"data"`
		} `json:"message"`
	}
	if err := json.Unmarshal(body, &msg); err != nil {
		return nil, fmt.Errorf("failed to parse message: %w", err)
	}

	decodedData, err := base64.StdEncoding.DecodeString(msg.Message.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode data: %w", err)
	}

	var event WebhookEvent
	if err := json.Unmarshal(decodedData, &event); err != nil {
		return nil, fmt.Errorf("failed to parse webhook data: %w", err)
	}

	return &event, nil
}
