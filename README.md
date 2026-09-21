# n8n-nodes-session-token-auth

An n8n credential type (plus a small helper node) for APIs shaped like this:

1. `POST` a login path with a username and password
2. The response contains a session token (e.g. `{ "sessionId": "..." }`)
3. Every subsequent request must send that token in a header — either
   HTTP Basic (`Authorization: Basic base64(username:token)`) or a raw
   custom header (e.g. `X-Session-Id: <token>`)

n8n's built-in credential store has no way to express this out of the box:
credential values are static, entered once in the UI, while a session token is
only known after a login call made at runtime. This credential type uses n8n's
`preAuthentication` hook to do that login once per credential entry (n8n stores
the token and re-runs the login after a `401`), then injects the token into
every request that uses the credential.

## What you get

- **Credential type "Session Token Auth API"** — use it on the HTTP Request
  node (*Authentication → Predefined Credential Type*) or on any node that
  accepts a predefined credential.
- **"Session Token Auth" HTTP Request preset** in the node palette — an HTTP
  Request node pre-wired to this credential.
- **"Session Token" node** with one operation, *Get Session Token* — performs
  the login and returns the token and the exact header the credential sends,
  for cases where you need the raw token (Code nodes, tools, nodes that only
  take a header value). The login runs on every execution of this node; only
  the credential itself caches the token.

## Credential fields

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
| Test Path | Optional authenticated `GET` endpoint used by the credential's **Test** button (e.g. `api/me`). The test always logs in first; without a Test Path it falls back to a `GET` on the Login Path, which many APIs reject even though the login succeeded. |

## Session Token node output

```json
{
  "sessionToken": "…",
  "username": "…",
  "header": { "name": "Authorization", "value": "Basic …" }
}
```

With *Continue on Fail* enabled, a failed item keeps the same shape with `null`
values plus an `error` message.

> **Security note.** This output is a live credential. n8n stores node output
> in the execution history in plain text, so anyone who can view the
> workflow's executions can read the token. Prefer the credential directly on
> an HTTP Request node; if you must use this node, consider turning off
> *Save successful executions* in the workflow settings.

## Install

From the n8n UI (self-hosted, Community Nodes enabled): *Settings → Community
nodes → Install* and enter `n8n-nodes-session-token-auth`.

Or manually, in n8n's user folder:

```bash
mkdir -p ~/.n8n/nodes && cd ~/.n8n/nodes && npm install n8n-nodes-session-token-auth
```

and restart n8n.

> **0.1.0 is not usable** — it contained only the credential type, which n8n's
> UI installer rejects ("does not contain any nodes"), and its login hook was
> never invoked because the credential did not declare the expirable
> `sessionToken` property n8n requires. Use 0.2.0 or later.

## Build from source

```bash
npm install --ignore-scripts
npm run build
```

## License

MIT — see [LICENSE](LICENSE).
