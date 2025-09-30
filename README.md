## GlowIn - Sign in with Apple (Flask POC)

This is a minimal Flask + HTML + Bootstrap + JS Proof-of-Concept integrating Sign in with Apple using the web authorization code flow (response_mode=form_post). It builds a client secret (ES256), exchanges the authorization code for tokens, and verifies the ID token via Apple JWKS.

### Features
- Apple OAuth web flow (authorize → token → verify)
- ES256 client secret generation with `.p8`
- ID token verification against Apple JWKS
- Nonce/state validation
- Live on-page console to view logs/events
- Dockerfile and docker-compose
- GitHub Actions CI: imports app and builds Docker image

### Requirements
- Python 3.12+
- Apple Developer account with:
  - Service ID (`APPLE_CLIENT_ID`, e.g., `com.throwin-glow.com`)
  - Team ID (`APPLE_TEAM_ID`)
  - Key ID (`APPLE_KEY_ID`)
  - Downloaded `.p8` key placed at `.keys/AuthKey_XXXXXX.p8`

### Configuration
Create `.env` (preferred) or use `env.txt` at repository root. Example:

```
# Core
DEBUG=False
SECRET_KEY=changeme-in-prod

# Apple Sign-In
APPLE_CLIENT_ID=com.YourApp.com
APPLE_TEAM_ID=YOUR_TEAM_ID
APPLE_KEY_ID=YOUR_KEY_ID
APPLE_PRIVATE_KEY_PATH=.keys/AuthKey_YourKeyID.p8
APPLE_REDIRECT_URI=https://YourSafeDomain.com/redirect
```

In Apple Developer → Identifiers → Service IDs, set:
- Redirect URI: `https://throwin-glow.com/redirect` (must match exactly)
- Scopes: `name email`

Place your `.p8` in `.keys/` and update `APPLE_PRIVATE_KEY_PATH` accordingly.

### Local run (without Docker)
```
python -m venv GlowIn/venv
GlowIn/venv/Scripts/activate  # Windows
pip install -r GlowIn/requirements.txt
python GlowIn/app.py
# http://127.0.0.1:5000
```

### Docker
Build and run with docker-compose (uses `../.env` by default in compose):
```
cd GlowIn
docker compose up --build
# App on http://localhost:5000
```

### What happens during sign-in
1. `/auth/apple/login` redirects to Apple with `response_type=code`, `response_mode=form_post`, `scope=name email`, `state`, and `nonce`.
2. Apple posts back to `/auth/apple/callback` with `code`, `state`, optional `user` JSON.
3. Server builds ES256 client_secret JWT and calls `https://appleid.apple.com/auth/token`.
4. Server verifies `id_token` signature and claims (iss/aud/iat/exp, optional nonce).
5. Session is created and user is redirected to `/home`.

### Live Console
Pages mirror `console.log/info/warn/error` into a floating panel. Toggle and clear are provided, plus global error/rejection capture.

### CI (GitHub Actions)
Workflow path: `.github/workflows/ci.yml`
- Installs dependencies, imports `GlowIn/app.py`, and builds Docker image.

### Notes
- Only the first Apple sign-in returns `user` details; store what you need immediately.
- Never commit your `.p8` key or real `.env`. See `.gitignore`/`.dockerignore`.


