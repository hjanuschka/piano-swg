package main

import (
	"flag"
	"log"
	"path/filepath"

	"yourusername/piano-demo/internal/config"
	"yourusername/piano-demo/internal/server"

	"github.com/joho/godotenv"
)

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
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Override debug setting from command line
	cfg.Debug = *debug

	// Create and start server
	srv := server.New(cfg)
	if err := srv.Start(); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
