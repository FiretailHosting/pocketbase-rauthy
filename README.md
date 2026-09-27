# pocketbase-sso

Opinionated OpenID Connect sign-in for PocketBase apps.
Only members of one provider group can sign in, sessions end a fixed time after the account's last OIDC sign-in, and password sign-in is off.

## Use

```sh
go get github.com/FiretailHosting/pocketbase-sso
```

```go
var authPolicy = sso.Config{RequiredGroup: "internal-admin", SessionMaxAge: 8 * time.Hour}

// at startup
if err := sso.Register(app, authPolicy); err != nil {
	log.Fatal(err)
}

// in one of the app's migrations
m.Register(func(app core.App) error { return sso.Migrate(app, authPolicy) }, nil)
```

`Collection` (name or ID, default `users`), `Provider` (`oidc`) and `LoginField` (`sso_login_at`) are optional.
Always use `Register` and `Migrate` together, with the same config.

Frontend: `pb.collection('users').authWithOAuth2({ provider: 'oidc' })`.
Show the error message on 403; a 401 from `auth-refresh` means the client must sign in again.
Other routes follow their normal signed-out behavior, which can include 404 for protected records or guest access to public data.

- **`Register`** requires the configured provider, membership in the `groups` claim, and a verified email.
  PocketBase creates or links the account and applies its normal OAuth2 profile mappings and `createData`.
  The verified email and login time cannot be overridden through `createData`.
  Account changes and the login time are rolled back if authentication fails.
  Direct API account creation requires superuser auth, even if the create rule is later loosened.
  Non-superusers cannot change the login time through record updates.
- **`Migrate`** turns password and OTP sign-in off and OAuth2 on, permits creation only in PocketBase's internal OAuth2 context or by superusers, and adds the login field.
  It leaves the provider config alone.

The session limit is **account-wide**, not per device or token.
A successful OIDC sign-in renews the window for that account's other still-valid tokens; each token's own expiration still applies.
After `SessionMaxAge`, HTTP requests are treated as signed out and existing realtime connections are closed before sending further protected messages.
Removing a user from the required group takes effect no later than this window ends, not immediately.

If you already applied an earlier version of this package's migration, call `Migrate` in a new application migration to update the OAuth2 create rule.

The superuser dashboard (`/_/`) still uses a password and is the way back in if the provider is down.

## Provider requirements

Configure an OpenID Connect provider for the auth collection in the PocketBase superuser dashboard.
It must supply a verified email and a `groups` array containing `RequiredGroup`.
The provider name in PocketBase must match `Config.Provider` (default `oidc`).
The package does not set the provider endpoints or credentials.

## Rauthy example

- Confidential client, authorization code flow, PKCE `S256`.
- Redirect URI `<app origin>/api/oauth2-redirect`.
- Scopes `openid email profile groups`, with `groups` as a default scope: PocketBase does not request it.

## PocketBase provider for Rauthy

`/_/` → the collection → Options → OAuth2 → OpenID Connect:

| Field | Value |
| --- | --- |
| Client ID / secret | from Rauthy |
| Auth URL | `https://auth.firetailhosting.com/auth/v1/oidc/authorize` |
| Token URL | `https://auth.firetailhosting.com/auth/v1/oidc/token` |
| User info URL | empty (reads the ID token) |
| JWKS verification URL | `https://auth.firetailhosting.com/auth/v1/oidc/certs` |
| Issuers | `https://auth.firetailhosting.com/auth/v1/` |

Set both the JWKS URL and issuers: without either, PocketBase omits the corresponding ID token signature or issuer check, and the package logs a startup warning.
If a userinfo URL is configured instead, PocketBase reads identity data from that endpoint rather than the ID token.

## Check

```sh
make check   # gofmt, vet, race tests, build
```

Tests cover signed OIDC exchanges against a local test provider, account linking, profile mappings, rollback, API guards, and realtime expiry.
A live identity provider is not part of the test suite.
