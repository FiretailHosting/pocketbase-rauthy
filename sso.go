// Package sso applies an opinionated OpenID Connect sign-in policy to a
// PocketBase auth collection. It requires group membership and a verified
// email, and limits sessions from the last successful sign-in.
package sso

import (
	"errors"
	"time"

	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/hook"
	"github.com/pocketbase/pocketbase/tools/types"
)

// Config describes which accounts may sign in and for how long.
type Config struct {
	// RequiredGroup is the OIDC group a user must be in, e.g. "internal-admin".
	RequiredGroup string
	// SessionMaxAge is how long sessions last after this account's last OIDC sign-in.
	SessionMaxAge time.Duration
	// Collection is the auth collection name or ID; defaults to "users".
	Collection string
	// Provider is the OAuth2 provider name in PocketBase; defaults to "oidc".
	Provider string
	// LoginField is the date field recording the last sign-in; defaults to
	// "sso_login_at".
	LoginField string
}

func (config Config) withDefaults() (Config, error) {
	if config.RequiredGroup == "" {
		return config, errors.New("sso: RequiredGroup is required")
	}
	if config.SessionMaxAge <= 0 {
		return config, errors.New("sso: SessionMaxAge must be positive")
	}
	if config.Collection == "" {
		config.Collection = "users"
	}
	if config.Provider == "" {
		config.Provider = "oidc"
	}
	if config.LoginField == "" {
		config.LoginField = "sso_login_at"
	}

	return config, nil
}

// Register binds the sign-in, session and account-creation hooks. Pair it with
// a migration calling [Migrate] with the same config.
func Register(app core.App, config Config) error {
	config, err := config.withDefaults()
	if err != nil {
		return err
	}

	app.OnServe().Bind(&hook.Handler[*core.ServeEvent]{
		Func: func(e *core.ServeEvent) error {
			warnIfTokensUnverified(e.App, config)

			// runs right after PocketBase loads the auth token, so every route,
			// authRefresh included, sees an expired session as signed out
			e.Router.Bind(&hook.Handler[*core.RequestEvent]{
				Priority: apis.DefaultLoadAuthTokenMiddlewarePriority + 1,
				Func: func(e *core.RequestEvent) error {
					if matchesCollection(e.Auth, config.Collection) && sessionExpired(e.Auth, config) {
						e.Auth = nil
					}

					return e.Next()
				},
			})

			return e.Next()
		},
	})

	app.OnRecordAuthWithOAuth2Request(config.Collection).BindFunc(func(e *core.RecordAuthWithOAuth2RequestEvent) error {
		return signIn(e, config)
	})

	// Keep the guard even if someone loosens the collection's create rule.
	// PocketBase assigns the OAuth2 context internally after our sign-in checks.
	app.OnRecordCreateRequest(config.Collection).BindFunc(func(e *core.RecordRequestEvent) error {
		info, err := e.RequestInfo()
		if err != nil {
			return err
		}
		if !e.HasSuperuserAuth() && info.Context != core.RequestInfoContextOAuth2 {
			return e.ForbiddenError("Accounts can only be created through the configured OIDC provider or by a superuser.", nil)
		}

		return e.Next()
	})

	app.OnRecordUpdateRequest(config.Collection).BindFunc(func(e *core.RecordRequestEvent) error {
		if !e.HasSuperuserAuth() && !e.Record.GetDateTime(config.LoginField).Equal(e.Record.Original().GetDateTime(config.LoginField)) {
			return e.ForbiddenError("The SSO login time is server-managed.", nil)
		}

		return e.Next()
	})

	// HTTP middleware cannot recheck an already-open realtime connection.
	app.OnRealtimeMessageSend().BindFunc(func(e *core.RealtimeMessageEvent) error {
		record, _ := e.Client.Get(apis.RealtimeClientAuthKey).(*core.Record)
		if matchesCollection(record, config.Collection) && sessionExpired(record, config) {
			return errors.New("sso: session expired") // PocketBase closes the connection
		}

		return e.Next()
	})

	return nil
}

func signIn(e *core.RecordAuthWithOAuth2RequestEvent, config Config) error {
	if e.ProviderName != config.Provider {
		return e.ForbiddenError("Sign in with the configured OIDC provider.", nil)
	}

	if !inGroup(e.OAuth2User.RawUser, config.RequiredGroup) {
		return e.ForbiddenError("Your account is not in the "+config.RequiredGroup+" group, which this app requires.", nil)
	}

	// PocketBase leaves the email empty unless the provider marks it verified.
	if e.OAuth2User.Email == "" {
		return e.ForbiddenError("The OIDC provider did not supply a verified email address for this account.", nil)
	}

	// Let PocketBase create and link accounts, including its profile mappings.
	// Roll back the login time and account changes if authentication fails.
	originalApp := e.App
	return originalApp.RunInTransaction(func(txApp core.App) error {
		e.App = txApp
		defer func() { e.App = originalApp }()

		now := types.NowDateTime()
		if e.Record == nil {
			if e.CreateData == nil {
				e.CreateData = map[string]any{}
			}
			// Client-supplied createData must not override these trusted values.
			e.CreateData[core.FieldNameEmail] = e.OAuth2User.Email
			e.CreateData[config.LoginField] = now
		} else {
			e.Record.Set(config.LoginField, now)
			if err := txApp.Save(e.Record); err != nil {
				return err
			}
		}

		return e.Next()
	})
}

// inGroup reports whether the provider's "groups" claim lists group.
func inGroup(rawUser map[string]any, group string) bool {
	groups, _ := rawUser["groups"].([]any)
	for _, member := range groups {
		if member == group {
			return true
		}
	}

	return false
}

func matchesCollection(record *core.Record, collection string) bool {
	return record != nil && (record.Collection().Name == collection || record.Collection().Id == collection)
}

func sessionExpired(record *core.Record, config Config) bool {
	loginAt := record.GetDateTime(config.LoginField)

	return loginAt.IsZero() || time.Since(loginAt.Time()) > config.SessionMaxAge
}

// warnIfTokensUnverified logs when ID token signature or issuer checks are missing.
// A configured userinfo endpoint bypasses ID token parsing in PocketBase.
func warnIfTokensUnverified(app core.App, config Config) {
	collection, err := app.FindCollectionByNameOrId(config.Collection)
	if err != nil || !collection.OAuth2.Enabled {
		return
	}

	provider, ok := collection.OAuth2.GetProviderConfig(config.Provider)
	if !ok {
		app.Logger().Warn("sso: no OAuth2 provider configured; nobody can sign in",
			"collection", config.Collection, "provider", config.Provider)
		return
	}

	if provider.UserInfoURL != "" {
		return
	}

	jwksURL, _ := provider.Extra["jwksURL"].(string)
	issuers, _ := provider.Extra["issuers"].([]any)
	if jwksURL == "" || len(issuers) == 0 {
		app.Logger().Warn("sso: ID token verification is incomplete (missing JWKS URL or issuers)",
			"collection", config.Collection, "provider", config.Provider)
	}
}
