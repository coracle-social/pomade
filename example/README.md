# Pomade Example Client

A full-featured example client application demonstrating the Pomade protocol using Mithril.js.

## Features

- **Sign Up**: Create a new account with email and password recovery (2-of-3 multisig)
- **Log In**: Access your existing account with email and password
- **Recover**: Retrieve your private key using email and password
- **Session Management**: View and delete active sessions
- **Email Simulation**: Visual inbox showing simulated recovery emails

## Architecture

This example app uses:

- **Mithril.js** - Lightweight UI framework
- **Local Relay** - Welshman's LOCAL_RELAY_URL for in-memory relay
- **Fake Signers** - 8 local signers running in the browser
- **In-Memory Storage** - No persistence, resets on page reload

## Running the Example

1. Install dependencies from the monorepo root:
   ```bash
   pnpm install
   ```

2. Build the core package:
   ```bash
   pnpm --filter @pomade/core build
   ```

3. Start the dev server:
   ```bash
   pnpm start:example
   ```

4. Open http://localhost:3000 in your browser

## Usage Flow

### Sign Up

1. Click "Sign Up" on the home screen
2. Enter an email and password
3. The app creates a 2-of-3 multisig account and sets up recovery
4. You're taken to the dashboard showing your active sessions

### Log In

1. Click "Log In" on the home screen
2. Enter your email and password
3. The app logs you in and takes you to the dashboard

### Recover Account

1. Click "Recover Account" on the home screen
2. Enter your email and password
3. Your private key (nsec) is displayed in a text box
4. Copy it to save it securely

### Dashboard

- View all active sessions with client and peer information
- Refresh the session list
- Delete individual sessions
- Click "Start Over" to return to the home screen

## How It Works

This example demonstrates the Pomade protocol's key features:

1. **Multisig Architecture**: Accounts use 2-of-3 threshold signing with Frost cryptography
2. **Recovery Protocol**: Email/password-based recovery without storing secrets centrally
3. **Session Management**: View and control which devices/sessions have access

The fake signers run entirely in the browser, and the local relay keeps all data in memory. This makes the example fully self-contained and easy to understand.

## Code Structure

```
example/
├── index.html              # HTML template with CSS
├── vite.config.js          # Vite configuration
├── package.json            # Dependencies
└── src/
    ├── main.js             # App entry point
    ├── state.js            # Application state
    ├── signers.js          # Fake signer setup
    ├── components/
    │   ├── EmailInbox.js   # Simulated email inbox
    │   └── StatusMessage.js # Status/error messages
    └── views/
        ├── Home.js         # Home screen with action buttons
        ├── Register.js     # Sign up flow
        ├── Login.js        # Login flow
        ├── Recovery.js     # Account recovery
        ├── Recovered.js    # Display recovered private key
        └── Dashboard.js    # Session management
```

## Notes

- This is a demonstration app with no persistence
- Passwords are not actually hashed (simplified for demo)
- The local relay and fake signers reset on page reload
- In production, signers would be separate services with proper security
- The app uses a fixed 2-of-3 configuration for simplicity
