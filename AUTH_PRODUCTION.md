# CRYSTAL authentication production runbook

## Required secrets

Set `MONGODB_URI`, `SESSION_SECRET`, and `TOTP_ENCRYPTION_KEY` only through the deployment secret store. Never commit them.

Set `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` and `MICROSOFT_CLIENT_ID` / `MICROSOFT_CLIENT_SECRET` in the same way.

## OAuth/OIDC

Register only the exact HTTPS callback URLs used by the deployed app. Keep OAuth state and OIDC nonce validation enabled. Do not accept arbitrary redirect targets.

## Password recovery

Password reset requests must return the same response whether or not an account exists. Reset tokens must be cryptographically random, single-use, securely stored, and short-lived. After a successful reset, invalidate existing sessions where appropriate.

## MFA

TOTP is compatible with standard authenticator applications. Require re-authentication before disabling or replacing MFA. Recovery codes must be single-use and stored as hashes. Do not provide an MFA bypass based only on an active session.

## Sessions

Use HTTPS in production and secure, HttpOnly, SameSite cookies. Rotate or invalidate sessions after credential changes and other high-risk events. Do not put session identifiers in URLs.

## Monitoring

Log authentication failures, password resets, MFA enrollment/replacement, recovery-code use, OAuth failures, and suspicious account activity without logging passwords, session cookies, OAuth secrets, TOTP secrets, or recovery codes.

## Deployment gate

Run tests and dependency/security checks before deployment. Treat this repository implementation as an authentication foundation and complete an application-specific security review before public launch.
