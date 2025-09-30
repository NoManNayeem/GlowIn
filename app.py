from __future__ import annotations

import json
import os
import time
import secrets
from pathlib import Path
from typing import Any, Dict, Optional

import requests
from dotenv import load_dotenv
from flask import (
    Flask,
    abort,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from urllib.parse import urlencode

import jwt
from jwt import PyJWKClient, InvalidTokenError


# --- App and environment setup ------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
ENV_PATH = BASE_DIR.parent / "env.txt"
DOTENV_PATH = BASE_DIR.parent / ".env"

# Prefer .env; fallback to env.txt without overriding existing values
load_dotenv(DOTENV_PATH)
load_dotenv(ENV_PATH, override=False)


def create_app() -> Flask:
    app = Flask(__name__)

    # Core config
    app.secret_key = os.getenv("SECRET_KEY", "change-me-in-dev")

    # Apple Sign-In configuration (env.txt names aligned to your file)
    app.config["APPLE_CLIENT_ID"] = os.getenv("APPLE_CLIENT_ID", "")
    app.config["APPLE_TEAM_ID"] = os.getenv("APPLE_TEAM_ID", "")
    app.config["APPLE_KEY_ID"] = os.getenv("APPLE_KEY_ID", "")
    app.config["APPLE_PRIVATE_KEY_PATH"] = os.getenv("APPLE_PRIVATE_KEY_PATH", "")
    # Use provided redirect or default to local dev
    app.config["APPLE_REDIRECT_URI"] = os.getenv(
        "APPLE_REDIRECT_URI", "https://YourSafeDomain.com/redirect"
    )

    # Endpoints from Apple (2025)
    app.config["APPLE_AUTH_URL"] = "https://appleid.apple.com/auth/authorize"
    app.config["APPLE_TOKEN_URL"] = "https://appleid.apple.com/auth/token"
    app.config["APPLE_KEYS_URL"] = "https://appleid.apple.com/auth/keys"

    register_routes(app)
    return app


# --- Helpers ------------------------------------------------------------------

def _read_private_key(p8_path: str) -> str:
    path = Path(p8_path)
    if not path.is_absolute():
        # Resolve relative to project root (Backend directory)
        path = (BASE_DIR.parent / path).resolve()
    if not path.exists():
        raise FileNotFoundError(f"Apple private key not found at: {path}")
    return path.read_text(encoding="utf-8")


def build_apple_client_secret(
    team_id: str,
    client_id: str,
    key_id: str,
    private_key_path: str,
    lifetime_seconds: int = 15552000,  # 180 days in seconds
) -> str:
    """
    Create the Apple OAuth client_secret JWT.
    Requirements (Apple docs, 2025):
      - alg: ES256, header kid=<key_id>
      - iss: <team_id>
      - sub: <client_id>
      - aud: https://appleid.apple.com
      - iat/exp: exp <= 180 days from iat
    """
    now = int(time.time())
    exp = now + min(lifetime_seconds, 15552000)

    claims = {
        "iss": team_id,
        "iat": now,
        "exp": exp,
        "aud": "https://appleid.apple.com",
        "sub": client_id,
    }

    private_key = _read_private_key(private_key_path)

    token = jwt.encode(
        payload=claims,
        key=private_key,
        algorithm="ES256",
        headers={"kid": key_id},
    )
    # PyJWT returns str for >= 2.x
    return token


def exchange_code_for_tokens(
    token_url: str,
    client_id: str,
    client_secret: str,
    code: str,
    redirect_uri: str,
) -> Dict[str, Any]:
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": redirect_uri,
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    resp = requests.post(token_url, data=data, headers=headers, timeout=15)
    if not resp.ok:
        raise RuntimeError(
            f"Apple token exchange failed: {resp.status_code} {resp.text}"
        )
    return resp.json()


def verify_apple_id_token(
    id_token: str,
    keys_url: str,
    audience_client_id: str,
) -> Dict[str, Any]:
    """
    Verify Apple's ID token using JWKS (Apple signs ID tokens with RS256).
    Checks: signature, issuer, audience, exp/iat.
    """
    jwks_client = PyJWKClient(keys_url)
    signing_key = jwks_client.get_signing_key_from_jwt(id_token)
    decoded = jwt.decode(
        id_token,
        signing_key.key,
        algorithms=["RS256"],
        audience=audience_client_id,
        issuer="https://appleid.apple.com",
        options={"require": ["iss", "aud", "exp", "iat", "sub"]},
    )
    return decoded


def require_config(app: Flask) -> None:
    missing = [
        k
        for k in [
            "APPLE_CLIENT_ID",
            "APPLE_TEAM_ID",
            "APPLE_KEY_ID",
            "APPLE_PRIVATE_KEY_PATH",
        ]
        if not app.config.get(k)
    ]
    if missing:
        raise RuntimeError(
            "Missing Apple Sign-In configuration values: " + ", ".join(missing)
        )


# --- Routes -------------------------------------------------------------------

def register_routes(app: Flask) -> None:
    @app.get("/")
    def index():
        if session.get("apple_user"):
            return redirect(url_for("home"))
        return redirect(url_for("login"))

    @app.get("/login")
    def login():
        # Render the login page with "Sign in with Apple" button
        return render_template(
            "auth_login_register.html",
            apple_client_id=app.config["APPLE_CLIENT_ID"],
            apple_redirect_uri=app.config["APPLE_REDIRECT_URI"],
        )

    @app.get("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.get("/home")
    def home():
        user = session.get("apple_user")
        return render_template("home.html", user=user)

    @app.get("/auth/apple/login")
    def apple_begin():
        require_config(app)

        state = secrets.token_urlsafe(24)
        nonce = secrets.token_urlsafe(24)
        session["apple_oauth_state"] = state
        session["apple_oauth_nonce"] = nonce

        params = {
            "response_type": "code",
            "response_mode": "form_post",
            "client_id": app.config["APPLE_CLIENT_ID"],
            "redirect_uri": app.config["APPLE_REDIRECT_URI"],
            "scope": "name email",
            "state": state,
            "nonce": nonce,
        }

        url = app.config["APPLE_AUTH_URL"] + "?" + urlencode(params)
        return redirect(url)

    @app.route("/auth/apple/callback", methods=["GET", "POST"])
    def apple_callback():
        require_config(app)

        # Apple recommends response_mode=form_post (POST). Support GET for safety.
        form = request.form if request.method == "POST" else request.args

        error = form.get("error")
        if error:
            # e.g., user_cancelled_authorize
            return render_template("auth_login_register.html", error=error), 400

        # CSRF state check
        state = form.get("state")
        expected_state = session.pop("apple_oauth_state", None)
        if not state or not expected_state or state != expected_state:
            abort(400, description="Invalid state")

        code = form.get("code")
        if not code:
            abort(400, description="Missing authorization code")

        # Build client_secret JWT
        client_secret = build_apple_client_secret(
            team_id=app.config["APPLE_TEAM_ID"],
            client_id=app.config["APPLE_CLIENT_ID"],
            key_id=app.config["APPLE_KEY_ID"],
            private_key_path=app.config["APPLE_PRIVATE_KEY_PATH"],
        )

        # Exchange code for tokens
        token_response = exchange_code_for_tokens(
            token_url=app.config["APPLE_TOKEN_URL"],
            client_id=app.config["APPLE_CLIENT_ID"],
            client_secret=client_secret,
            code=code,
            redirect_uri=app.config["APPLE_REDIRECT_URI"],
        )

        id_token = token_response.get("id_token")
        if not id_token:
            abort(400, description="Missing id_token from Apple response")

        try:
            decoded = verify_apple_id_token(
                id_token=id_token,
                keys_url=app.config["APPLE_KEYS_URL"],
                audience_client_id=app.config["APPLE_CLIENT_ID"],
            )
        except InvalidTokenError as e:
            abort(400, description=f"Invalid id_token: {str(e)}")

        # Verify nonce if present (OIDC best practice)
        expected_nonce = session.pop("apple_oauth_nonce", None)
        token_nonce = decoded.get("nonce")
        if token_nonce is not None and expected_nonce != token_nonce:
            abort(400, description="Invalid nonce")

        # Optional: user info comes only once in 'user' field on first sign-in
        raw_user = form.get("user")
        parsed_user: Optional[Dict[str, Any]] = None
        if raw_user:
            try:
                parsed_user = json.loads(raw_user)
            except json.JSONDecodeError:
                parsed_user = None

        session["apple_user"] = {
            "sub": decoded.get("sub"),
            "email": decoded.get("email"),
            "email_verified": decoded.get("email_verified"),
            "is_private_email": decoded.get("is_private_email"),
            "raw_user": parsed_user,
            "tokens": {
                "access_token": token_response.get("access_token"),
                "refresh_token": token_response.get("refresh_token"),
                "expires_in": token_response.get("expires_in"),
                # Do NOT store id_token long-term in production
            },
        }

        return redirect(url_for("home"))


app = create_app()


if __name__ == "__main__":
    # Flask dev server
    app.run(host="127.0.0.1", port=5000, debug=os.getenv("DEBUG", "False").lower() == "true")


