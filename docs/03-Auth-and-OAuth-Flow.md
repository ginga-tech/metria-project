# Auth and OAuth Flow

## Token Model

- JWT is generated on backend after login/signup/OAuth callback.
- Token includes `sub` and `email` claims.
- Expiration and validation are controlled by `Jwt__*` settings.

## Email and Password

- Signup: `POST /api/auth/signup`
- Login: `POST /api/auth/login`

Validation highlights:

- Email format validation
- Password minimum length at signup
- SHA-256 hash comparison for login

## Google OAuth

Entry point:

1. Front opens `GET /api/auth/google/start?redirectUri=<front-callback>`
2. Backend redirects to Google authorization endpoint
3. Google redirects to backend callback: `/api/auth/google/callback`
4. Backend exchanges code for token, resolves user info, and redirects to frontend with `#token=...`

Backend callback URL is built from:

- `BACKEND_BASE_URL` or config fallback

Frontend redirect priority:

1. `state` param decoded from `redirectUri`
2. `FRONTEND_CALLBACK` / `FrontendCallback`
3. `FRONTEND_ORIGIN` + `/oauth/callback`
4. local fallback `http://localhost:5173/oauth/callback`

## Production OAuth Checklist

- `GOOGLE_CLIENT_ID` configured in backend
- `GOOGLE_CLIENT_SECRET` configured in backend
- Google Console redirect URI:
  - `https://SEU-BACKEND/api/auth/google/callback`
- Frontend origin/domain aligned with backend OAuth configuration
