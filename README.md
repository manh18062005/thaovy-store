Auth API (demo)

Endpoints (demo implementation):

- POST /api/login
  - body: { username, password, deviceName }
  - returns: { accessToken, sessionId, expiresIn }
  - sets an HttpOnly `refreshToken` cookie for refresh / logout flows

- POST /api/refresh
  - body: { refreshToken }
  - returns: { accessToken, expiresIn }

  - If no `refreshToken` is provided in body, the server will try to read the HttpOnly `refreshToken` cookie.

- POST /api/logout
  - body: { refreshToken } OR { username, sessionId }
  - returns: { ok: true }

  - If client used cookie-based refresh token, server will clear the cookie on logout.

- GET /api/sessions[?username]
  - returns list of active sessions (refresh tokens are not exposed)

- GET /api/protected
  - header: Authorization: Bearer <accessToken>

Notes:
- This is a minimal demo. Replace `demoUsers` and authentication logic with your real user database and secure password hashing.
- `sessions.json` stores active refresh tokens per user; in production use a database.
- Set `JWT_SECRET` env var to a strong secret before running in production.
- To run (from `server/`):

```powershell
npm install
npm run start-auth
```
 
Configuration for production (when frontend is hosted on Netlify or elsewhere):

- Set `AUTH_ORIGINS` to a comma-separated list of allowed origins (example: `https://thaovystore.netlify.app`). The auth server will use this for CORS.
- When deploying the auth server to HTTPS, set `NODE_ENV=production` (or `COOKIE_SECURE=true`) so refresh cookies are set with `SameSite=None; Secure` which is required for cross-site cookies.
- On Netlify, set `AUTH_SERVER_URL` to your deployed auth server URL (for example `https://my-auth.example.com`) and ensure frontend uses `window.AUTH_SERVER_URL` or that you rebuild with the correct value.

Example Netlify env set commands:

```powershell
netlify env:set AUTH_SERVER_URL "https://my-auth.example.com"
netlify env:set AUTH_ORIGINS "https://thaovystore.netlify.app"
netlify env:set NODE_ENV production
```
# Support Proxy (ThaoVyStore)

This small Express proxy keeps your OpenAI API key on the server and relays chat requests from the client.

1. Install dependencies

```bash
cd server
npm install
```

2. Set your OpenAI API key in environment variable `OPENAI_API_KEY` (example for Windows PowerShell):

```powershell
$env:OPENAI_API_KEY = "sk-..."
npm start
```

Or create a `.env` file in the `server/` folder with:

```
OPENAI_API_KEY=sk-...
```

3. Start the server

```bash
npm start
```

4. Client

The client (`support.js`) calls `POST /api/support` with JSON `{ messages: [...] }`. The proxy will forward to OpenAI and return `{ result: "..." }`.

Security notes:
- Do NOT commit your `.env` or API key to source control.
- In production, restrict CORS to your domain and add authentication if needed.
