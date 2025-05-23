# 🎹 Piano Demo Integration

A Go application that handles user creation and subscription management between Subscribe with Google (SwG) and Piano.

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔐 User Creation | Creates Piano users from SwG reader IDs |
| 🔄 Subscription Events | Handles subscription start/cancel/renew events via webhook |
| ⚙️ Environment Config | Flexible environment-based configuration |
| 🔗 Subscription Linking | Allows users to link Piano subscriptions with Google accounts for enhanced content visibility |

## 📑 Table of Contents

- [Features](#-features)
- [Quick Start](#-quick-start)
- [Prerequisites](#-prerequisites)
- [Configuration](#-configuration)
- [Tutorial: Setting up Google Cloud Console](#-tutorial-setting-up-google-cloud-console)
  - [Create a Google Cloud Project](#1-create-a-google-cloud-project)
  - [Enable Required APIs](#2-enable-required-apis)
  - [Configure OAuth 2.0](#3-configure-oauth-20)
  - [Set up Service Account](#4-set-up-service-account)
  - [Configure Developer Access](#5-configure-developer-access)
  - [Set up Pub/Sub Notifications](#6-set-up-pubsub-notifications)
  - [Configure Publisher Center](#7-configure-publisher-center)
  - [Update Environment Variables](#8-update-environment-variables)
  - [Test the Integration](#9-test-the-integration)
- [Docker Setup](#-docker-setup)
- [API Endpoints](#-api-endpoints)
  - [POST /swg/create-user](#post-swgcreate-user)
  - [POST /swg/webhook](#post-swgwebhook)
  - [POST /swg/check-linking-shown](#post-swgcheck-linking-shown)
  - [POST /swg/set-linking-shown](#post-swgset-linking-shown)
- [Dependencies](#-dependencies)
- [Subscription Linking](#-subscription-linking)
  - [Prerequisites](#prerequisites)
  - [Implementation Example](#implementation-example)
- [License](#-license)



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

### POST /swg/check-linking-shown

Checks if the subscription linking prompt has already been shown to a user.

Request body:
```json
{
    "piano_id": "string"
}
```

Response:
```json
{
    "shown": true|false
}
```

### POST /swg/set-linking-shown

Sets a flag indicating that the subscription linking prompt has been shown to a user.

Request body:
```json
{
    "piano_id": "string"
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

## 🔄 Subscription Linking

The subscription linking feature allows users to link their existing Piano subscriptions with their Google accounts. 

> With the Subscription Linking API in Reader Revenue Manager (RRM), paying readers can link their subscriptions with publishers and web publishers to their Google accounts. Content from their paid subscriptions will then be highlighted in Google Search, Discover, and other Google products.

### Prerequisites

1. **Create Custom Field in Piano**:
   - Log in to your Piano dashboard
   - Navigate to "Settings" > "Custom Fields"
   - Click "Create Field"
   - Set field name: `swg_linking_shown`
   - Set type: "Boolean"
   - Set default value: "false"

2. **Configure ea-standalone.js**:
   - Ensure the `ea-standalone.js` script is properly loaded on your pages
   - This script initializes the SwG client and provides the necessary `callSwg` function
   - The script should be configured with your publication ID and appropriate event handlers

3. **API Endpoints**:
   - `/swg/check-linking-shown`: Checks if a user has already been shown the linking prompt
   - `/swg/set-linking-shown`: Sets the flag indicating that a user has been shown the linking prompt

### Implementation Example

1. **Include ea-standalone.js in your page**:

```html
<script src="/static/ea-standalone.js"></script>
```

This script provides the `window.callSwg` function needed for subscription operations and initializes the SwG client.

2. **Add subscription linking code to your page**:

```javascript
function showSubLinking(subscriptions) {
  // Check if Piano is loaded and user is valid
  if (typeof tp === 'undefined' || typeof tp.pianoId === 'undefined' || !tp.pianoId.isUserValid()) {
    return false;
  }
  
  const pianoId = tp.pianoId.getUser().uid;
  
  // Check if linking already shown
  fetch('/swg/check-linking-shown', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ piano_id: pianoId }),
  })
  .then(response => response.json())
  .then(data => {
    if (!data.shown) {
      // If not shown, trigger the linking process
      subscriptions
        .linkSubscription({
          publisherProvidedId: pianoId,
        })
        .then(result => {
          if (result.success) {
            // Set the flag that linking was shown
            fetch('/swg/set-linking-shown', {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
              },
              body: JSON.stringify({ piano_id: pianoId }),
            });
          }
        })
        .catch(error => console.error('Linking error:', error));
    }
  })
  .catch(error => console.error('Check linking error:', error));
  
  return true;
}

// Usage with ea-standalone.js
window.callSwg(function(subscriptions) {
  setTimeout(() => {
    showSubLinking(subscriptions);
  }, 5000);
});
```

Note: The `window.callSwg` function is provided by ea-standalone.js, which also ensures that the necessary Google scripts are loaded and configured correctly.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🐳 Docker Setup

The project includes Docker support for both development and production environments.

### Development Mode

1. Start the development environment:
   ```bash
   docker-compose up
   ```

   This will:
   - Build the development container
   - Generate SSL certificates automatically
   - Mount your local code for hot-reloading
   - Cache Go dependencies between builds
   - Start the application on https://localhost:8080

2. For subsequent runs, you can use:
   ```bash
   docker-compose up --build  # Force rebuild
   docker-compose up -d      # Run in background
   ```

3. Stop the development environment:
   ```bash
   docker-compose down
   ```

### Production Mode

1. Build the production image:
   ```bash
   docker build -t pedal-demo .
   ```

2. Run the container:
   ```bash
   docker run -p 8080:8080 \
     --env-file .env \
     pedal-demo
   ```
