package rauthy

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tests"
	"github.com/pocketbase/pocketbase/tools/auth"
	"github.com/pocketbase/pocketbase/tools/types"
)

var testConfig = Config{RequiredGroup: "internal-admin", SessionMaxAge: 8 * time.Hour}

// newApp returns an empty app with the migration applied and the hooks bound.
func newApp(t testing.TB) *tests.TestApp {
	t.Helper()

	app, err := tests.NewTestApp(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := Migrate(app, testConfig); err != nil {
		t.Fatal(err)
	}
	if err := Register(app, testConfig); err != nil {
		t.Fatal(err)
	}

	return app
}

func saveUser(t testing.TB, app core.App, email string, loginAt time.Time) *core.Record {
	t.Helper()

	users, err := app.FindCollectionByNameOrId("users")
	if err != nil {
		t.Fatal(err)
	}

	record := core.NewRecord(users)
	record.SetEmail(email)
	record.SetRandomPassword()
	record.SetVerified(true)
	if !loginAt.IsZero() {
		loginAt, _ := types.ParseDateTime(loginAt)
		record.Set("sso_login_at", loginAt)
	}
	if err := app.Save(record); err != nil {
		t.Fatal(err)
	}

	return record
}

// signInEvent runs the OAuth2 sign-in hooks the way PocketBase's route does,
// after it has fetched the user from Rauthy and looked up any existing record.
func signInEvent(t testing.TB, app core.App, provider string, user *auth.AuthUser, existing *core.Record) (*core.RecordAuthWithOAuth2RequestEvent, bool, error) {
	t.Helper()

	users, err := app.FindCollectionByNameOrId("users")
	if err != nil {
		t.Fatal(err)
	}

	event := new(core.RecordAuthWithOAuth2RequestEvent)
	event.RequestEvent = &core.RequestEvent{App: app}
	event.Collection = users
	event.ProviderName = provider
	event.OAuth2User = user
	event.Record = existing
	event.IsNewRecord = existing == nil

	var reachedPocketBase bool
	err = app.OnRecordAuthWithOAuth2Request().Trigger(event, func(e *core.RecordAuthWithOAuth2RequestEvent) error {
		reachedPocketBase = true
		return nil
	})

	return event, reachedPocketBase, err
}

func rauthyUser(email string, groups ...any) *auth.AuthUser {
	return &auth.AuthUser{Id: "sub-" + email, Email: email, RawUser: map[string]any{"groups": groups}}
}

func TestFirstSignInCreatesTheAccount(t *testing.T) {
	app := newApp(t)
	defer app.Cleanup()

	event, reached, err := signInEvent(t, app, "oidc", rauthyUser("new@example.com", "internal-admin"), nil)
	if err != nil || !reached {
		t.Fatalf("sign-in: reached=%v err=%v", reached, err)
	}

	record, err := app.FindAuthRecordByEmail("users", "new@example.com")
	if err != nil {
		t.Fatalf("account not created: %v", err)
	}
	if record.Id != event.Record.Id || !record.Verified() {
		t.Errorf("created record id=%q verified=%v, event record id=%q", record.Id, record.Verified(), event.Record.Id)
	}
	if record.GetDateTime("sso_login_at").IsZero() {
		t.Error("sign-in time not recorded")
	}
}

func TestSignInLinksAnExistingAccount(t *testing.T) {
	app := newApp(t)
	defer app.Cleanup()

	existing := saveUser(t, app, "old@example.com", time.Time{})

	event, reached, err := signInEvent(t, app, "oidc", rauthyUser("old@example.com", "internal-admin"), existing)
	if err != nil || !reached {
		t.Fatalf("sign-in: reached=%v err=%v", reached, err)
	}
	if event.Record.Id != existing.Id {
		t.Errorf("signed in as %q, want the existing %q", event.Record.Id, existing.Id)
	}

	total, _ := app.CountRecords("users")
	if total != 1 {
		t.Errorf("%d users, want 1", total)
	}

	reloaded, _ := app.FindRecordById("users", existing.Id)
	if reloaded.GetDateTime("sso_login_at").IsZero() {
		t.Error("sign-in time not recorded")
	}
}

func TestSignInIsRefused(t *testing.T) {
	cases := []struct {
		name     string
		provider string
		user     *auth.AuthUser
		message  string
	}{
		{"outside the group", "oidc", rauthyUser("a@example.com", "customers"), "not in the internal-admin group"},
		{"no groups claim", "oidc", &auth.AuthUser{Id: "sub", Email: "a@example.com", RawUser: map[string]any{}}, "not in the internal-admin group"},
		{"unverified email", "oidc", rauthyUser("", "internal-admin"), "verified email"},
		{"another provider", "github", rauthyUser("a@example.com", "internal-admin"), "Sign in with Rauthy"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			app := newApp(t)
			defer app.Cleanup()

			_, reached, err := signInEvent(t, app, c.provider, c.user, nil)
			if reached {
				t.Error("refused sign-in reached PocketBase")
			}
			if err == nil || !strings.Contains(err.Error(), c.message) {
				t.Errorf("err = %v, want it to mention %q", err, c.message)
			}

			if total, _ := app.CountRecords("users"); total != 0 {
				t.Errorf("%d users created, want 0", total)
			}
		})
	}
}

func TestSessionsEndAfterSessionMaxAge(t *testing.T) {
	cases := []struct {
		name    string
		loginAt time.Time
		status  int
	}{
		{"recent sign-in", time.Now().Add(-time.Hour), http.StatusOK},
		{"sign-in too long ago", time.Now().Add(-9 * time.Hour), http.StatusUnauthorized},
		{"never signed in through Rauthy", time.Time{}, http.StatusUnauthorized},
	}

	for _, c := range cases {
		app := newApp(t)
		user := saveUser(t, app, "user@example.com", c.loginAt)
		token, err := user.NewAuthToken()
		if err != nil {
			t.Fatal(err)
		}

		scenario := tests.ApiScenario{
			Name:            c.name,
			Method:          http.MethodPost,
			URL:             "/api/collections/users/auth-refresh",
			Headers:         map[string]string{"Authorization": token},
			ExpectedStatus:  c.status,
			ExpectedContent: []string{`"`},
			TestAppFactory:  func(testing.TB) *tests.TestApp { return app },
		}
		scenario.Test(t)
	}
}

func TestPasswordSignInIsOff(t *testing.T) {
	app := newApp(t)
	saveUser(t, app, "user@example.com", time.Time{})

	scenario := tests.ApiScenario{
		Method:          http.MethodPost,
		URL:             "/api/collections/users/auth-with-password",
		Body:            strings.NewReader(`{"identity":"user@example.com","password":"anything"}`),
		ExpectedStatus:  http.StatusForbidden,
		ExpectedContent: []string{"not configured to allow password authentication"},
		TestAppFactory:  func(testing.TB) *tests.TestApp { return app },
	}
	scenario.Test(t)
}

func TestAccountsCannotBeCreatedThroughTheAPI(t *testing.T) {
	app := newApp(t)

	// loosen the rule the way someone might at runtime
	users, _ := app.FindCollectionByNameOrId("users")
	anyone := ""
	users.CreateRule = &anyone
	if err := app.Save(users); err != nil {
		t.Fatal(err)
	}

	scenario := tests.ApiScenario{
		Method:          http.MethodPost,
		URL:             "/api/collections/users/records",
		Body:            strings.NewReader(`{"email":"x@example.com","password":"12345678901","passwordConfirm":"12345678901"}`),
		ExpectedStatus:  http.StatusForbidden,
		ExpectedContent: []string{"only be created by a superuser"},
		TestAppFactory:  func(testing.TB) *tests.TestApp { return app },
	}
	scenario.Test(t)
}

func TestMigrateKeepsTheProviderConfig(t *testing.T) {
	app, err := tests.NewTestApp(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Cleanup()

	users, _ := app.FindCollectionByNameOrId("users")
	users.OAuth2.Providers = []core.OAuth2ProviderConfig{{Name: "oidc", ClientId: "client", ClientSecret: "secret", AuthURL: "https://auth.example.com/a", TokenURL: "https://auth.example.com/t"}}
	if err := app.Save(users); err != nil {
		t.Fatal(err)
	}

	// twice, to show re-running is harmless
	for range 2 {
		if err := Migrate(app, testConfig); err != nil {
			t.Fatal(err)
		}
	}

	users, _ = app.FindCollectionByNameOrId("users")
	if users.PasswordAuth.Enabled || users.OTP.Enabled || !users.OAuth2.Enabled || users.CreateRule != nil {
		t.Errorf("password=%v otp=%v oauth2=%v createRule=%v", users.PasswordAuth.Enabled, users.OTP.Enabled, users.OAuth2.Enabled, users.CreateRule)
	}
	if users.Fields.GetByName("sso_login_at") == nil {
		t.Error("sso_login_at field missing")
	}
	if provider, ok := users.OAuth2.GetProviderConfig("oidc"); !ok || provider.ClientId != "client" {
		t.Errorf("provider config lost: %+v", provider)
	}
}

func TestConfigNeedsGroupAndMaxAge(t *testing.T) {
	if _, err := (Config{SessionMaxAge: time.Hour}).withDefaults(); err == nil {
		t.Error("missing RequiredGroup accepted")
	}
	if _, err := (Config{RequiredGroup: "g"}).withDefaults(); err == nil {
		t.Error("missing SessionMaxAge accepted")
	}
}
