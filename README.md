# pocketbase-rauthy

Rauthy (OpenID Connect) sign-in for PocketBase apps. Only members of one Rauthy group can sign in, sessions end a fixed time after the last Rauthy sign-in, and password sign-in is off.

## Use

```sh
go get github.com/FiretailHosting/pocketbase-rauthy
```

```go
var sso = rauthy.Config{RequiredGroup: "internal-admin", SessionMaxAge: 8 * time.Hour}

// at startup
if err := rauthy.Register(app, sso); err != nil {
	log.Fatal(err)
}

// in one of the app's migrations
m.Register(func(app core.App) error { return rauthy.Migrate(app, sso) }, nil)
```

`Collection` (default `users`), `Provider` (`oidc`) and `LoginField` (`sso_login_at`) are optional.

Frontend: `pb.collection('users').authWithOAuth2({ provider: 'oidc' })`. Show the error message on 403; a 401 means the session ended, so sign in again.

- **`Register`** allows sign-in only through the provider, with the group in the `groups` claim and a verified email. A first sign-in creates the account; an existing account with the same email is linked. Any request after `SessionMaxAge` is treated as signed out. API account creation needs superuser auth.
- **`Migrate`** turns password and OTP sign-in off and OAuth2 on, makes creation superuser-only, and adds the login field. It leaves the provider config alone.

The superuser dashboard (`/_/`) still uses a password and is the way back in if Rauthy is down.

## Rauthy client

- Confidential client, authorization code flow, PKCE `S256`.
- Redirect URI `<app origin>/api/oauth2-redirect`.
- Scopes `openid email profile groups`, with `groups` as a default scope: PocketBase does not request it.

## PocketBase provider

`/_/` → the collection → Options → OAuth2 → OpenID Connect:

| Field | Value |
| --- | --- |
| Client ID / secret | from Rauthy |
| Auth URL | `https://auth.firetailhosting.com/auth/v1/oidc/authorize` |
| Token URL | `https://auth.firetailhosting.com/auth/v1/oidc/token` |
| User info URL | empty (reads the ID token) |
| JWKS verification URL | `https://auth.firetailhosting.com/auth/v1/oidc/certs` |
| Issuers | `https://auth.firetailhosting.com/auth/v1/` |

Without the JWKS URL and issuers, PocketBase does not verify the ID token; a warning is logged at startup.

## Check

```sh
make check   # gofmt, vet, race tests, build
```
