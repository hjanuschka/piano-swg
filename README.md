# 🎹 Piano Demo Integration

A Go application that handles user creation and subscription management between Subscribe with Google (SwG) and Piano.

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔐 User Creation | Creates Piano users from SwG reader IDs |
| 🔄 Subscription Events | Handles subscription start/cancel/renew events via webhook |
| ⚙️ Environment Config | Flexible environment-based configuration |

## 🚀 Quick Start

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/piano-demo.git
   cd piano-demo
   ```

2. Install dependencies:
   ```bash
   go mod download
   ```

3. Configure your environment:
   ```bash
   cp .env.example .env
   # Edit .env with your credentials
   ```

4. Run the application:
   ```bash
   go run lab/demo/pedal-demo.go
   ```

5. Visit the demo page:
   ```
   https://localhost:8080/demo
   ```

## 📋 Prerequisites

- Go 1.16 or later
- Piano API credentials
- Google API credentials
- Access to Subscribe with Google API
- Piano requires LinkedTerms and Access-Token-Creation feature enabled (ask your account manager)

## 🛠️ Configuration

### Required Environment Variables

| Variable | Description |
|----------|-------------|
| `PIANO_AID` | Your Piano AID |
| `PIANO_API_TOKEN` | Your Piano API token |
| `PIANO_JWT_SECRET` | Your Piano JWT secret |
| `PIANO_REST_KEY` | Your Piano REST key |
| `PIANO_TYPE` | Your Piano type (sandbox, id, or id-eu) |
| `PIANO_PRIVATE_KEY` | Your Piano private key |
| `COOKIE_DOMAIN` | Domain for cookie setting |
| `GOOGLE_AUTH_JSON` | Google API credentials JSON |

### Optional Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SERVER_ADDRESS` | Server address | ":8080" |
| `DEBUG` | Enable debug logging | false |
| `COOKIE_EXPIRE` | Cookie expiration duration | "720h" |

## 📚 Tutorial: Setting up Google Cloud Console

### 1. Create a Google Cloud Project

1. Go to the [Google Cloud Console](https://console.cloud.google.com)
2. Create a new project or select an existing one
3. Note down your project ID

### 2. Enable Required APIs

1. Enable the Subscribe with Google Developer API:
   - Visit: `https://console.cloud.google.com/apis/library/subscribewithgoogledeveloper.googleapis.com/?project=PROJECT_ID`
   - Click "Enable"

### 3. Configure OAuth 2.0

1. Go to "APIs & Services" > "Credentials"
2. Click "Create Credentials" > "OAuth client ID"
3. Configure the OAuth consent screen:
   - Set application type as "Web application"
   - Add authorized JavaScript origins (your domain)
   - Add authorized redirect URIs
4. Save your client ID and client secret

### 4. Set up Service Account

1. Go to "APIs & Services" > "Credentials"
2. Click "Create Credentials" > "Service Account"
3. Fill in service account details
4. Grant the following roles:
   - Subscribe with Google Developer
   - Service Account User
5. Create and download the JSON key file
6. Save the JSON content as `GOOGLE_AUTH_JSON` in your `.env` file

### 5. Configure Developer Access

1. Go to "IAM & Admin" > "IAM"
2. Add your developers' email addresses
3. Grant them the "Subscribe with Google Developer" role
4. Developers can now access the SwG developer tools at:
   `https://news.google.com/swg/dev/SWG_PUBLICATION_ID`

### 6. Set up Pub/Sub Notifications

1. Go to "Pub/Sub" > "Topics"
2. Create a new topic for SwG notifications
3. Create a subscription for the topic
4. Configure the subscription to push to your webhook endpoint:
   `https://your-domain.com/swg/webhook`

### 7. Configure Publisher Center

1. Go to the [Publisher Center](https://publishercenter.google.com)
2. Add your publication
3. Configure your website ownership
4. Set up your subscription products
5. Note down your `publicationId` and `productId`

### 8. Update Environment Variables

Add the following to your `.env` file:

```env
# Google API Configuration
GOOGLE_AUTH_JSON=your_service_account_json_here
PUBLICATION_ID=your_publication_id_here
PRODUCT_ID=your_product_id_here

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
COOKIE_DOMAIN=your_domain_here
COOKIE_EXPIRE=720h
```

### 9. Test the Integration

1. Start the application:
   ```bash
   go run lab/demo/pedal-demo.go
   ```

2. Open your browser and navigate to:
   ```
   https://localhost:8080/demo
   ```

3. You should see the demo page with:
   - A "Subscribe with Google" button
   - A paywall message
   - The SwG integration working with your Piano setup

4. Test the integration by:
   - Clicking the "Subscribe with Google" button
   - Completing the Google sign-in process
   - Verifying that the user is created in Piano
   - Checking that the subscription status is synchronized

Note: Make sure you have valid SSL certificates in the `certs` directory (`server.crt` and `server.key`) for HTTPS to work properly.

## 🔌 API Endpoints

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


## 📦 Dependencies

- [github.com/caarlos0/env](https://github.com/caarlos0/env) - Environment variable parsing
- [github.com/golang-jwt/jwt](https://github.com/golang-jwt/jwt) - JWT token handling
- [github.com/joho/godotenv](https://github.com/joho/godotenv) - .env file loading
- [golang.org/x/oauth2/google](https://golang.org/x/oauth2/google) - Google OAuth2 support

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

