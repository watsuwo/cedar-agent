# Keycloak × cedar-agent — login-time ABAC demo (AuthZEN)

This demo plugs a custom **Keycloak Authenticator (Java SPI)** into the browser
login flow. Right after the username/password step, the authenticator calls the
forked **cedar-agent** over the [AuthZEN](https://openid.github.io/authzen/)
`POST /access/v1/evaluation` API to decide — **per client** — whether the user is
allowed to log in, using **attribute-based** Cedar policies.

```
 Browser ──login──▶ Keycloak ──┐
                               │  AuthZEN /access/v1/evaluation
   (auth-username-password-form)│  subject=user(+attrs) action=login resource=Client
                               ▼
                          cedar-agent (PDP) ── Cedar ABAC policies
                               │
        decision=true ─▶ context.success()  ─▶ redirect to app (allowed)
        decision=false ─▶ context.failure(ACCESS_DENIED) ─▶ "access denied" page
```

## What it shows

`resource` = the Keycloak **client** the user is logging into. `subject` = the
user plus attributes. Cedar policies grant login per client based on those
attributes and the request context:

| Client | Cedar policy (granted when) |
|--------|------------------------------|
| `internal-portal` | `user_type == "employee"` **and** `context.access_route == "internal"` |
| `partner-portal`  | `user_type == "partner"` **and** `organization == "globex"` |
| `public-app`      | any authenticated user |

Demo users (password = `password` for all):

| User | user_type | organization |
|------|-----------|--------------|
| `alice` | employee | acme |
| `bob` | partner | globex |
| `carol` | contractor | initech |

## Components

| Service | Port (host) | Purpose |
|---------|-------------|---------|
| `keycloak` | http://localhost:8088 | Keycloak 26.1 + the AuthZEN authenticator + imported `authzen-demo` realm |
| `cedar-agent` | http://localhost:8181 | AuthZEN PDP, seeded with `policies/policies.json` |
| `app` | http://localhost:9000 | Static landing page = OAuth redirect target (shown when login is allowed) |

> Ports 8088/8181 are used to avoid clashing with anything already on 8080/8180.
> Inside the compose network Keycloak always reaches the PDP at
> `http://cedar-agent:8180` (see the `authzen-config` authenticator config).

## Run

```shell
cd demo/keycloak-authzen
docker compose up --build
```

First boot builds the SPI jar (Maven) and the cedar-agent image, then imports the
realm. Keycloak admin console: http://localhost:8088 (`admin` / `admin`).

## Try it (browser)

Open an authorize URL for a client and log in as one of the users:

```
http://localhost:8088/realms/authzen-demo/protocol/openid-connect/auth?client_id=CLIENT&redirect_uri=http://localhost:9000/&response_type=code&scope=openid
```

Replace `CLIENT` with `internal-portal`, `partner-portal`, or `public-app`.

- **Allowed** → you are redirected to the `app` landing page (with an auth code).
- **Denied** → Keycloak shows an "access denied" page; the login does not complete.

Expected outcomes (local access is classified as `internal`):

| user \ client | internal-portal | partner-portal | public-app |
|---------------|:---:|:---:|:---:|
| alice (employee/acme) | ✅ | ❌ | ✅ |
| bob (partner/globex)  | ❌ | ✅ | ✅ |
| carol (contractor)    | ❌ | ❌ | ✅ |

Watch the decisions flow through both services:

```shell
docker compose logs -f keycloak    | grep "AuthZEN decision"
docker compose logs -f cedar-agent | grep "AuthZEN evaluation"
```

## AuthZEN request shape

The authenticator sends, for each login:

```json
{
  "subject":  { "type": "User", "id": "alice",
                "properties": { "user_type": "employee", "organization": "acme" } },
  "action":   { "name": "login" },
  "resource": { "type": "Client", "id": "internal-portal" },
  "context":  { "ip": "192.168.65.1", "access_route": "internal" }
}
```

`access_route` is derived from the remote IP (loopback / RFC 1918 ⇒ `internal`,
otherwise `external`) — a demo-grade heuristic.

## Editing policies live

cedar-agent keeps policies in memory; update them without a rebuild:

```shell
curl -X PUT -H "Content-Type: application/json" \
  -d @policies/policies.json http://localhost:8181/v1/policies
```

Then log in again to see the new decision. You can also inspect the PDP directly:

```shell
curl http://localhost:8181/.well-known/authzen-configuration
curl http://localhost:8181/v1/policies
curl -X POST http://localhost:8181/access/v1/evaluation -H 'content-type: application/json' -d '{
  "subject":{"type":"User","id":"alice","properties":{"user_type":"employee"}},
  "action":{"name":"login"},
  "resource":{"type":"Client","id":"internal-portal"},
  "context":{"access_route":"internal"}}'
```

## Layout

```
authenticator/   Keycloak Authenticator SPI (Maven, Java 17)
keycloak/        Dockerfile (multi-stage: build jar → Keycloak image + realm import)
realm/           authzen-demo realm export (clients, users+attributes, custom browser flow)
policies/        Cedar ABAC policies (cedar-agent --policies format)
app/             static landing page for the allowed redirect
docker-compose.yml
```

## How the login flow is wired

The realm import defines a custom top-level browser flow `browser-authzen` whose
`forms` subflow runs `auth-username-password-form` (REQUIRED) then
`authzen-access-evaluation` (REQUIRED), and sets it as the realm's browser flow.
The authenticator's PDP URL / action / resource type / fail-open are configured
via the `authzen-config` authenticator config in the realm export.

## Notes / not production-ready

- The PDP call has no TLS or auth header, and fails **closed** by default
  (`failOpen=false`); tune timeouts and add transport security for real use.
- Custom user attributes rely on the realm enabling **unmanaged attributes**
  (set in the imported realm's user-profile config).
- AuthZEN Search APIs and writing the decision into tokens (claim mappers) are
  out of scope.
