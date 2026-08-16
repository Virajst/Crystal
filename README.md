# CRYSTAL Authentication

CRYSTAL now includes a starter authentication service with:

- Email/password accounts using Argon2id
- Google OpenID Connect sign-in through Passport
- Microsoft sign-in through Passport OAuth/OIDC
- Session authentication stored in MongoDB
- TOTP MFA compatible with Google Authenticator and Microsoft Authenticator
- QR-code enrollment
- Encrypted TOTP secrets (AES-256-GCM)
- Ten one-time recovery codes, stored hashed
- Login rate limiting and secure HTTP headers

## Run locally

1. Install Node.js 20+ and MongoDB.
2. Copy `.env.example` to `.env`.
3. Generate a 32-byte TOTP encryption key:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
```

4. Set `SESSION_SECRET`, `MONGODB_URI`, and `TOTP_ENCRYPTION_KEY`.
5. Run:

```bash
npm install
npm start
```

Open `http://localhost:3000`.

## Google setup

Create a Google OAuth web client and register `http://localhost:3000/auth/google/callback`. Put its client ID and secret in `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET`.

## Microsoft setup

Register a web application in Microsoft Entra ID and add `http://localhost:3000/auth/microsoft/callback`. Set `MICROSOFT_CLIENT_ID`, `MICROSOFT_CLIENT_SECRET`, and optionally `MICROSOFT_TENANT` in `.env`.

## Production notes

Use HTTPS, a strong random session secret, managed MongoDB, and production callback URLs. Never commit `.env` or provider secrets. Before production launch, add centralized logging, CSRF protection for password/account-changing endpoints, email verification, password reset, abuse controls, and a security review.

The Google and Microsoft integrations use their OAuth/OIDC provider flows rather than impersonating those providers.
