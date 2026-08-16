# CRYSTAL Authentication Security Checklist

- [x] Passwords hashed with a password-hashing algorithm; never store plaintext passwords.
- [x] OAuth/OIDC callback URLs are configuration values, not hard-coded secrets.
- [x] OAuth state/nonce validation is required.
- [x] Session cookies use HttpOnly/Secure/SameSite settings in production.
- [x] TOTP secrets are encrypted at rest.
- [x] Recovery codes are one-time use and should be stored as hashes.
- [x] Authentication endpoints are rate limited.
- [x] Login and recovery responses should not reveal whether an account exists.
- [x] Sensitive account changes require re-authentication.
- [x] Password reset tokens must be random, single-use, stored securely, and expire.
- [x] Secrets belong in environment variables / a secret manager, never source control.
- [ ] Configure HTTPS before production.
- [ ] Configure a real email provider for verification/password reset.
- [ ] Configure Google and Microsoft OAuth applications and exact redirect URIs.
- [ ] Run dependency and SAST checks in CI.
- [ ] Perform a production security review before exposing the service publicly.

The checklist follows OWASP authentication, MFA, and password-recovery guidance.
