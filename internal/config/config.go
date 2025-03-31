package config

import (
	"fmt"
	"time"

	"github.com/caarlos0/env"
)

// Config represents the application configuration
type Config struct {
	// Piano Configuration
	AID            string `env:"PIANO_AID,required"`
	APIToken       string `env:"PIANO_API_TOKEN,required"`
	JWTSecret      string `env:"PIANO_JWT_SECRET,required"`
	RestKey        string `env:"PIANO_REST_KEY,required"`
	PianoType      string `env:"PIANO_TYPE,required"`
	PrivateKey     string `env:"PIANO_PRIVATE_KEY,required"`
	TrinityEmptyID string `env:"TRINITY_EMPTY_ID" envDefault:"00000000-0000-0000-0000-000000000000"`

	// Server Configuration
	Address      string        `env:"SERVER_ADDRESS" envDefault:":8080"`
	Debug        bool          `env:"DEBUG" envDefault:"false"`
	CookieDomain string        `env:"COOKIE_DOMAIN,required"`
	CookieExpire time.Duration `env:"COOKIE_EXPIRE" envDefault:"720h"`

	// Product Configuration
	ProductID     string `env:"PRODUCT_ID" envDefault:"krone.at:showcase"`
	PublicationID string `env:"PUBLICATION_ID" envDefault:"krone.at"`

	// Google Configuration
	GoogleAuthJSON string `env:"GOOGLE_AUTH_JSON,required"`
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
	if c.GoogleAuthJSON == "" {
		return fmt.Errorf("Google auth configuration is required")
	}
	return nil
}

// Load loads configuration from environment variables
func Load() (*Config, error) {
	cfg := &Config{}
	if err := env.Parse(cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return cfg, nil
}
