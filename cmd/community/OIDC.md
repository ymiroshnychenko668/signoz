# Community sign-in with Keycloak

Set `COMMUNITY_OIDC_CONFIG_FILE` to a mounted JSON file and use the opaque session provider. Configure a confidential OpenID Connect client for the authorization code flow with S256 PKCE. Register the exact URL formed by appending `/api/v1/community-oidc/callback` to the public SigNoz URL. Include verified email and full group paths in the ID token.

```json
{
  "issuer": "https://identity.example.org/realms/observability",
  "clientId": "observability",
  "publicURL": "https://observability.example.org",
  "clientSecretFile": "/run/secrets/oidc-client",
  "orgId": "e7e944e5-f67c-435b-9c5b-aab8b3a549e6",
  "groupRoles": {
    "/observability/viewers": "signoz-viewer",
    "/observability/editors": "signoz-editor",
    "/observability/admins": "signoz-admin"
  },
  "links": {},
  "maxSessionSeconds": 900
}
```

Use the existing organization's UUID. The server must trust the issuer's TLS certificate and reach its discovery, token and signing key endpoints. Mount the client secret in a private file. Restart the server after changing the configuration or secret.

Registered groups authorize access. When several groups match, admin precedes editor and viewer. The organization, issuer and immutable subject identify each user. On first sign-in a user with an unused email receives a local account. To migrate an existing active account, verify its owner and add an explicit `links` entry from that person's Keycloak subject to the local user UUID. Reserve root for local recovery. Restrict its password endpoint to the recovery network. Service-account credentials and telemetry ingestion retain their own authentication.

On each sign-in SigNoz reconciles the individual's roles. Access and refresh tokens expire by the earlier of the verified ID token expiry or `maxSessionSeconds` after sign-in (60–3600). Disabling a user or removing a group at the issuer takes effect by that deadline for existing sessions. Signing out ends the local SigNoz session. Keycloak manages its browser session separately.

The browser completes a short-lived, single-use handoff on the instance that began the flow. Use one instance or sticky routing for login, callback and completion. When a server restart interrupts a handoff, start sign-in again.
