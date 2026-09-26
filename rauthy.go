// Package rauthy signs users in to a PocketBase app through Rauthy (OpenID
// Connect) and nowhere else. Membership of one Rauthy group decides who gets
// in, and sessions end a fixed time after the last Rauthy sign-in, so removing
// someone from the group locks them out.
package rauthy

import (
	"errors"
	"net/http"
	"time"

	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/hook"
	"github.com/pocketbase/pocketbase/tools/types"
)

// Config describes which accounts may sign in and for how long.
type Config struct {
	// RequiredGroup is the Rauthy group a user must be in, e.g. "internal-admin".
	RequiredGroup string
	// SessionMaxAge is how long a session lasts after the last Rauthy sign-in.
	SessionMaxAge time.Duration
	// Collection is the auth collection; defaults to "users".
	Collection string
	// Provider is the OAuth2 provider name in PocketBase; defaults to "oidc".
	Provider string
	// LoginField is the date field recording the last sign-in; defaults to
	// "sso_login_at".
	LoginField string
}

func (config Config) withDefaults() (Config, error) {
	if config.RequiredGroup == "" {
		return config, errors.New("rauthy: RequiredGroup is required")
	}
	if config.SessionMaxAge <= 0 {
		return config, errors.New("rauthy: SessionMaxAge must be positive")
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
					if e.Auth != nil && e.Auth.Collection().Name == config.Collection && sessionExpired(e.Auth, config) {
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

	// The collection's create rule is superuser-only, but a rule can be edited
	// at runtime; this keeps accounts from being created through the API anyway.
	app.OnRecordCreateRequest(config.Collection).BindFunc(func(e *core.RecordRequestEvent) error {
		if !e.HasSuperuserAuth() {
			return e.Error(http.StatusForbidden, "Accounts can only be created by a superuser.", nil)
		}

		return e.Next()
	})

	return nil
}

func signIn(e *core.RecordAuthWithOAuth2RequestEvent, config Config) error {
	if e.ProviderName != config.Provider {
		return e.ForbiddenError("Sign in with Rauthy.", nil)
	}

	if !inGroup(e.OAuth2User.RawUser, config.RequiredGroup) {
		return e.ForbiddenError("Your account is not in the "+config.RequiredGroup+" group, which this app requires.", nil)
	}

	// PocketBase leaves the email empty unless Rauthy marks it verified
	if e.OAuth2User.Email == "" {
		return e.ForbiddenError("Rauthy did not supply a verified email address for this account.", nil)
	}

	// PocketBase's own sign-up goes through the create request, which the guard
	// above rejects, so first sign-ins create the account here instead. An
	// existing account with the same email arrives as e.Record and is linked.
	if e.Record == nil {
		e.Record = core.NewRecord(e.Collection)
		e.Record.SetEmail(e.OAuth2User.Email)
		e.Record.SetRandomPassword()
		e.Record.SetVerified(true)
	}

	e.Record.Set(config.LoginField, types.NowDateTime())
	if err := e.App.Save(e.Record); err != nil {
		return err
	}

	return e.Next()
}

// inGroup reports whether Rauthy's "groups" claim lists group.
func inGroup(rawUser map[string]any, group string) bool {
	groups, _ := rawUser["groups"].([]any)
	for _, member := range groups {
		if member == group {
			return true
		}
	}

	return false
}

func sessionExpired(record *core.Record, config Config) bool {
	loginAt := record.GetDateTime(config.LoginField)

	return loginAt.IsZero() || time.Since(loginAt.Time()) > config.SessionMaxAge
}

// warnIfTokensUnverified logs when the provider is set up without a JWKS URL
// or issuers, in which case PocketBase reads the ID token without checking its
// signature or issuer.
func warnIfTokensUnverified(app core.App, config Config) {
	collection, err := app.FindCollectionByNameOrId(config.Collection)
	if err != nil || !collection.OAuth2.Enabled {
		return
	}

	provider, ok := collection.OAuth2.GetProviderConfig(config.Provider)
	if !ok {
		app.Logger().Warn("rauthy: no OAuth2 provider configured; nobody can sign in",
			"collection", config.Collection, "provider", config.Provider)
		return
	}

	jwksURL, _ := provider.Extra["jwksURL"].(string)
	issuers, _ := provider.Extra["issuers"].([]any)
	if jwksURL == "" || len(issuers) == 0 {
		app.Logger().Warn("rauthy: provider has no JWKS URL or issuers, so ID tokens are not verified",
			"collection", config.Collection, "provider", config.Provider)
	}
}
