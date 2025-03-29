# Piano Demo Integration

This Go application provides a bridge between Subscribe with Google (SwG) and Piano, handling user creation and subscription management.

## Features

- User creation and management
- Subscription status synchronization
- Secure token handling
- Graceful server shutdown
- Structured logging
- Environment-based configuration

## Prerequisites

- Go 1.16 or later
- Piano API credentials
- Google API credentials
- Access to Subscribe with Google API

## Configuration

Create a `.env` file in the project root with the following variables:

```env
# Piano API Configuration
PIANO_AID=your_aid_here
PIANO_API_TOKEN=your_api_token_here
PIANO_JWT_SECRET=your_jwt_secret_here
PIANO_REST_KEY=your_rest_key_here
PIANO_TYPE=your_piano_type_here
PIANO_PRIVATE_KEY=your_private_key_here

# Server Configuration
SERVER_ADDRESS=:8080
DEBUG=false
COOKIE_DOMAIN=localhost
COOKIE_EXPIRE=720h

# Google API Configuration
GOOGLE_AUTH_JSON=your_google_auth_json_here
```

### Required Environment Variables

- `PIANO_AID`: Your Piano AID
- `PIANO_API_TOKEN`: Your Piano API token
- `PIANO_JWT_SECRET`: Your Piano JWT secret
- `PIANO_REST_KEY`: Your Piano REST key
- `PIANO_TYPE`: Your Piano type
- `PIANO_PRIVATE_KEY`: Your Piano private key
- `COOKIE_DOMAIN`: Domain for cookie setting
- `GOOGLE_AUTH_JSON`: Google API credentials JSON

### Optional Environment Variables

- `SERVER_ADDRESS`: Server address (default: ":8080")
- `DEBUG`: Enable debug logging (default: false)
- `COOKIE_EXPIRE`: Cookie expiration duration (default: "720h")

## Installation

1. Clone the repository
2. Install dependencies:
   ```bash
   go mod download
   ```
3. Configure your environment variables in `.env`
4. Run the application:
   ```bash
   go run lab/demo/pedal-demo.go
   ```

## API Endpoints

### POST /swg/create-user

Creates a new user in Piano based on SwG reader ID.

Request body:
```json
{
    "reader_id": "string"
}
```

Response:
```json
{
    "status": "success",
    "data": {
        "status": "OK",
        "email": "user@example.com",
        "piano_id": "string"
    }
}
```

### POST /swg/webhook

Handles SwG webhook events for subscription status updates.

Request body:
```json
{
    "message": {
        "data": "base64_encoded_data"
    }
}
```

Response:
```json
{
    "status": "success",
    "data": null
}
```

## Error Handling

The application uses structured error responses:

```json
{
    "status": "error",
    "error": "error message"
}
```

## Security

- All endpoints require POST method
- Secure cookie settings (HttpOnly, Secure, SameSite)
- JWT token handling
- Environment-based configuration
- Graceful error handling

## Logging

The application provides structured logging with:
- Request/response logging
- Error logging
- Debug logging (when enabled)
- Panic recovery

## Dependencies

- github.com/caarlos0/env
- github.com/golang-jwt/jwt
- github.com/joho/godotenv
- golang.org/x/oauth2/google

## License

[Your License Here]