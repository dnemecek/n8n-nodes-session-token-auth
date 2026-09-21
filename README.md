# n8n-nodes-session-token-auth

An n8n Credential Type for APIs shaped like this:

1. `POST` a login path with a username and password
2. The response contains a session token (e.g. `{ "sessionId": "..." }`)
3. Every subsequent request must send that token in a header — either
   HTTP Basic (`Authorization: Basic base64(username:token)`) or a raw
   custom header (e.g. `X-Session-Id: <token>`)

n8n's built-in Credential Store doesn't have a way to express this out of the
box: credential values are static, entered once in the UI, while a session
token is only known after a login call made at runtime. This credential type
uses n8n's `preAuthentication` hook to do that login once per credential
entry (n8n caches and refreshes it automatically), then injects the resulting
token into every request that uses the credential.

## Fields

| Field | Purpose |
|---|---|
| Base URL | Must be `https://`. Login Path is appended to it. |
| Login Path | Path that performs the login, e.g. `login` or `auth/session`. |
| Login HTTP Method | `POST` or `GET`. GET always sends credentials as query params. |
| Login Body Type | For POST only: `JSON`, `Form-Urlencoded`, or `None` (HTTP Basic Auth on the login request itself). |
| Username / Password | Your login credentials. |
| Username Field / Password Field | Key names used in the login request body. |
| Token Field | Dot-path to the token in the login response, e.g. `sessionId`. |
| Username Field (in Login Response) | Optional — if the server echoes back a canonical username to use afterwards. |
| Header Format | `Basic` (base64 of `username:token`) or `Raw Token`. |
| Header Name | Header sent on every request, e.g. `Authorization` or `X-Session-Id`. |

## Install

```bash
npm install n8n-nodes-session-token-auth
```

Or, on a self-hosted n8n instance with Community Nodes enabled, install it
by package name (`n8n-nodes-session-token-auth`) from the n8n UI.

## Build from source

```bash
npm install
npm run build
```

## License

MIT — see [LICENSE](LICENSE).
