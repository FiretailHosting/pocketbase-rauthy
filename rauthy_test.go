package rauthy

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tests"
	"github.com/pocketbase/pocketbase/tools/auth"
	"github.com/pocketbase/pocketbase/tools/types"
)

var testConfig = Config{RequiredGroup: "internal-admin", SessionMaxAge: 8 * time.Hour}

func newApp(t testing.TB, config Config) *tests.TestApp {
	t.Helper()
	app, err := tests.NewTestApp(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Cleanup)
	if err := Migrate(app, config); err != nil {
		t.Fatal(err)
	}
	if err := Register(app, config); err != nil {
		t.Fatal(err)
	}
	return app
}

func usersCollection(t testing.TB, app core.App) *core.Collection {
	t.Helper()
	users, err := app.FindCollectionByNameOrId("users")
	if err != nil {
		t.Fatal(err)
	}
	return users
}

func save(t testing.TB, app core.App, model core.Model) {
	t.Helper()
	if err := app.Save(model); err != nil {
		t.Fatal(err)
	}
}

func saveUser(t testing.TB, app core.App, email string, loginAt time.Time) *core.Record {
	t.Helper()
	record := core.NewRecord(usersCollection(t, app))
	record.SetEmail(email)
	record.SetRandomPassword()
	record.SetVerified(true)
	record.Set("sso_login_at", loginAt.Truncate(time.Millisecond))
	save(t, app, record)
	return record
}

func authToken(t testing.TB, record *core.Record) string {
	t.Helper()
	token, err := record.NewAuthToken()
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func router(t testing.TB, app core.App) http.Handler {
	t.Helper()
	r, err := apis.NewRouter(app)
	if err != nil {
		t.Fatal(err)
	}
	if err := app.OnServe().Trigger(&core.ServeEvent{App: app, Router: r}); err != nil {
		t.Fatal(err)
	}
	mux, err := r.BuildMux()
	if err != nil {
		t.Fatal(err)
	}
	return mux
}

func request(t testing.TB, handler http.Handler, method, path, token string, body any, status int) *httptest.ResponseRecorder {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(method, path, bytes.NewReader(data))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", token)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != status {
		t.Fatalf("%s %s: got %d, want %d: %s", method, path, w.Code, status, w.Body.String())
	}
	return w
}

func assertCount(t testing.TB, app core.App, collection string, want int64) {
	t.Helper()
	count, err := app.CountRecords(collection)
	if err != nil {
		t.Fatal(err)
	}
	if count != want {
		t.Fatalf("%s: got %d records, want %d", collection, count, want)
	}
}

func claims() map[string]any {
	return map[string]any{
		"sub": "subject", "email": "user@example.com", "email_verified": true,
		"name": "New User", "groups": []string{"internal-admin"},
		"iss": "https://rauthy.example.test/", "aud": "client", "exp": time.Now().Add(time.Hour).Unix(),
	}
}

// Exercise PocketBase's actual token exchange, signed ID token validation, and
// account creation/linking. Only the external identity provider is simulated.
func configureProvider(t testing.TB, app core.App, claims map[string]any) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	encode := base64.RawURLEncoding.EncodeToString
	unsigned := encode([]byte(`{"alg":"EdDSA","kid":"test"}`)) + "." + encode(payload)
	idToken := unsigned + "." + encode(ed25519.Sign(privateKey, []byte(unsigned)))
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var body string
		switch r.URL.Path {
		case "/token":
			body = fmt.Sprintf(`{"access_token":"test","token_type":"Bearer","id_token":%q}`, idToken)
		case "/jwks":
			body = fmt.Sprintf(`{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"test","alg":"EdDSA","x":%q}]}`, encode(publicKey))
		default:
			http.NotFound(w, r)
			return
		}
		if _, err := io.WriteString(w, body); err != nil {
			t.Errorf("provider response: %v", err)
		}
	}))
	t.Cleanup(provider.Close)
	users := usersCollection(t, app)
	users.OAuth2.Providers = []core.OAuth2ProviderConfig{{
		Name: "oidc", ClientId: "client", ClientSecret: "secret",
		AuthURL: provider.URL + "/authorize", TokenURL: provider.URL + "/token",
		Extra: map[string]any{"jwksURL": provider.URL + "/jwks?key=" + encode(publicKey), "issuers": []string{"https://rauthy.example.test/"}},
	}}
	save(t, app, users)
}

func oauthLogin(t testing.TB, handler http.Handler, createData map[string]any, status int) *httptest.ResponseRecorder {
	t.Helper()
	return request(t, handler, http.MethodPost, "/api/collections/users/auth-with-oauth2", "", map[string]any{
		"provider": "oidc", "code": "test", "redirectURL": "http://localhost/callback", "createData": createData,
	}, status)
}

func TestSignInCreatesAndLinksAccounts(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(fmt.Sprintf("existing=%v", existing), func(t *testing.T) {
			app := newApp(t, testConfig)
			var existingID string
			if existing {
				existingID = saveUser(t, app, "user@example.com", time.Time{}).Id
			}
			configureProvider(t, app, claims())
			users := usersCollection(t, app)
			users.Fields.Add(&core.TextField{Name: "display_name", Required: true})
			users.Fields.Add(&core.TextField{Name: "department"})
			users.OAuth2.MappedFields.Name = "display_name"
			// Existing records need not have a mapped name to sign in.
			if existing {
				users.Fields.GetByName("display_name").(*core.TextField).Required = false
			}
			save(t, app, users)
			handler := router(t, app)
			body := oauthLogin(t, handler, map[string]any{
				"department": "engineering", "email": "attacker@example.com", "sso_login_at": "2099-01-01 00:00:00.000Z",
			}, http.StatusOK).Body.Bytes()
			var response struct {
				Token string `json:"token"`
				Meta  struct {
					IsNew bool `json:"isNew"`
				} `json:"meta"`
				Record struct {
					ID string `json:"id"`
				} `json:"record"`
			}
			if err := json.Unmarshal(body, &response); err != nil {
				t.Fatal(err)
			}
			record, err := app.FindAuthRecordByToken(response.Token)
			if err != nil {
				t.Fatal(err)
			}
			if response.Record.ID != record.Id || response.Meta.IsNew == existing || !record.Verified() || record.Email() != "user@example.com" {
				t.Fatalf("unexpected auth response: %s", body)
			}
			if existing && record.Id != existingID {
				t.Fatal("created a new account instead of linking the existing one")
			}
			if !existing && (record.GetString("display_name") != "New User" || record.GetString("department") != "engineering") {
				t.Fatal("profile mapping or createData was lost")
			}
			age := time.Since(record.GetDateTime("sso_login_at").Time())
			if age < 0 || age > time.Minute {
				t.Fatalf("login time was not set by the server: age=%v", age)
			}
			links, err := app.FindAllExternalAuthsByRecord(record)
			if err != nil {
				t.Fatal(err)
			}
			if len(links) != 1 || links[0].Provider() != "oidc" || links[0].ProviderId() != "subject" {
				t.Fatalf("unexpected external-auth links: %+v", links)
			}
			assertCount(t, app, "users", 1)
			request(t, handler, http.MethodPost, "/api/collections/users/auth-refresh", response.Token, nil, http.StatusOK)
			// A repeat sign-in reuses both the record and the external-auth link.
			oauthLogin(t, handler, nil, http.StatusOK)
			assertCount(t, app, "users", 1)
			assertCount(t, app, core.CollectionNameExternalAuths, 1)
		})
	}
}

func TestSignInIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name    string
		claim   string
		value   any
		status  int
		message string
	}{
		{"outside group", "groups", []string{"customers"}, http.StatusForbidden, "not in the internal-admin group"},
		{"missing groups", "groups", nil, http.StatusForbidden, "not in the internal-admin group"},
		{"malformed groups", "groups", "internal-admin", http.StatusForbidden, "not in the internal-admin group"},
		{"unverified email", "email_verified", false, http.StatusForbidden, "verified email"},
		{"missing email", "email", "", http.StatusForbidden, "verified email"},
		{"wrong issuer", "iss", "https://other.example.test/", http.StatusBadRequest, "Failed to fetch OAuth2 user"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := newApp(t, testConfig)
			user := claims()
			user[tc.claim] = tc.value
			configureProvider(t, app, user)
			response := oauthLogin(t, router(t, app), nil, tc.status)
			if !strings.Contains(response.Body.String(), tc.message) {
				t.Fatalf("missing error %q: %s", tc.message, response.Body.String())
			}
			assertCount(t, app, "users", 0)
			assertCount(t, app, core.CollectionNameExternalAuths, 0)
		})
	}
}

func TestOtherProviderIsRefused(t *testing.T) {
	app := newApp(t, testConfig)
	event := &core.RecordAuthWithOAuth2RequestEvent{}
	event.RequestEvent = &core.RequestEvent{App: app}
	event.Collection = usersCollection(t, app)
	event.ProviderName = "github"
	event.OAuth2User = &auth.AuthUser{Email: "user@example.com", RawUser: claims()}
	err := app.OnRecordAuthWithOAuth2Request().Trigger(event, func(*core.RecordAuthWithOAuth2RequestEvent) error {
		t.Error("refused provider reached PocketBase")
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "Sign in with Rauthy") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFailedSignInRollsBack(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(fmt.Sprintf("existing=%v", existing), func(t *testing.T) {
			app := newApp(t, testConfig)
			var original *core.Record
			if existing {
				original = saveUser(t, app, "user@example.com", time.Now().Add(-24*time.Hour))
			}
			configureProvider(t, app, claims())
			users := usersCollection(t, app)
			// PocketBase evaluates AuthRule after account creation and linking.
			rule := "id = ''"
			users.AuthRule = &rule
			save(t, app, users)
			oauthLogin(t, router(t, app), nil, http.StatusForbidden)
			assertCount(t, app, core.CollectionNameExternalAuths, 0)
			if !existing {
				assertCount(t, app, "users", 0)
				return
			}
			reloaded, err := app.FindRecordById("users", original.Id)
			if err != nil {
				t.Fatal(err)
			}
			if !reloaded.GetDateTime("sso_login_at").Equal(original.GetDateTime("sso_login_at")) {
				t.Fatal("failed sign-in changed the login time")
			}
			assertCount(t, app, "users", 1)
		})
	}
}

func TestSessionsEndAfterSessionMaxAge(t *testing.T) {
	for _, collection := range []string{"users", "_pb_users_auth_"} {
		for _, tc := range []struct {
			name          string
			loginAt       time.Time
			refreshStatus int
			viewStatus    int
		}{
			{"recent", time.Now().Add(-time.Hour), http.StatusOK, http.StatusOK},
			{"expired", time.Now().Add(-9 * time.Hour), http.StatusUnauthorized, http.StatusNotFound},
			{"never signed in", time.Time{}, http.StatusUnauthorized, http.StatusNotFound},
		} {
			t.Run(collection+"/"+tc.name, func(t *testing.T) {
				config := testConfig
				config.Collection = collection
				app := newApp(t, config)
				users := usersCollection(t, app)
				rule := "id = @request.auth.id"
				users.ViewRule = &rule
				save(t, app, users)
				user := saveUser(t, app, "user@example.com", tc.loginAt)
				token := authToken(t, user)
				handler := router(t, app)
				request(t, handler, http.MethodPost, "/api/collections/users/auth-refresh", token, nil, tc.refreshStatus)
				request(t, handler, http.MethodGet, "/api/collections/users/records/"+user.Id, token, nil, tc.viewStatus)
			})
		}
	}
}

func TestLoginTimeIsServerManaged(t *testing.T) {
	app := newApp(t, testConfig)
	users := usersCollection(t, app)
	rule := "id = @request.auth.id"
	users.UpdateRule = &rule
	save(t, app, users)
	user := saveUser(t, app, "user@example.com", time.Now().Add(-time.Hour))
	token := authToken(t, user)
	handler := router(t, app)
	path := "/api/collections/users/records/" + user.Id
	for _, date := range []string{"2099-01-01 00:00:00.000Z", types.NowDateTime().String(), ""} {
		request(t, handler, http.MethodPatch, path, token, map[string]any{"sso_login_at": date}, http.StatusForbidden)
	}
	request(t, handler, http.MethodPatch, path, token, map[string]any{"name": "Updated profile"}, http.StatusOK)
	reloaded, err := app.FindRecordById("users", user.Id)
	if err != nil {
		t.Fatal(err)
	}
	if !reloaded.GetDateTime("sso_login_at").Equal(user.GetDateTime("sso_login_at")) || reloaded.GetString("name") != "Updated profile" {
		t.Fatal("timestamp protection changed normal profile updates")
	}
}

func TestAPIAccountCreationRequiresSuperuser(t *testing.T) {
	app := newApp(t, testConfig)
	users := usersCollection(t, app)
	// Even a loosened rule and client-supplied context cannot bypass the guard.
	rule := ""
	users.CreateRule = &rule
	save(t, app, users)
	handler := router(t, app)
	body := map[string]any{"email": "new@example.com", "password": "12345678901", "passwordConfirm": "12345678901", "context": "oauth2"}
	response := request(t, handler, http.MethodPost, "/api/collections/users/records?context=oauth2", "", body, http.StatusForbidden)
	if !strings.Contains(response.Body.String(), "only be created through Rauthy or by a superuser") {
		t.Fatal(response.Body.String())
	}
	assertCount(t, app, "users", 0)
	superusers, err := app.FindCollectionByNameOrId(core.CollectionNameSuperusers)
	if err != nil {
		t.Fatal(err)
	}
	admin := core.NewRecord(superusers)
	admin.SetEmail("admin@example.com")
	admin.SetRandomPassword()
	save(t, app, admin)
	token := authToken(t, admin)
	request(t, handler, http.MethodPost, "/api/collections/users/records", token, body, http.StatusOK)
	user, err := app.FindAuthRecordByEmail("users", "new@example.com")
	if err != nil {
		t.Fatal(err)
	}
	request(t, handler, http.MethodPatch, "/api/collections/users/records/"+user.Id, token, map[string]any{"sso_login_at": types.NowDateTime()}, http.StatusOK)
}

func TestPasswordAndOTPSignInAreOff(t *testing.T) {
	app := newApp(t, testConfig)
	handler := router(t, app)
	request(t, handler, http.MethodPost, "/api/collections/users/auth-with-password", "", map[string]any{"identity": "user@example.com", "password": "anything"}, http.StatusForbidden)
	request(t, handler, http.MethodPost, "/api/collections/users/request-otp", "", map[string]any{"email": "user@example.com"}, http.StatusForbidden)
}

func TestRealtimeStopsAfterSessionExpiry(t *testing.T) {
	app := newApp(t, testConfig)
	users := usersCollection(t, app)
	rule := "@request.auth.id != ''"
	users.ListRule = &rule
	save(t, app, users)
	user := saveUser(t, app, "user@example.com", time.Now())
	server := httptest.NewServer(router(t, app))
	defer server.Close()
	client := &http.Client{Timeout: 5 * time.Second}
	response, err := client.Get(server.URL + "/api/realtime")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	scanner := bufio.NewScanner(response.Body)
	var connection struct {
		ClientID string `json:"clientId"`
	}
	for scanner.Scan() {
		if line := scanner.Text(); strings.HasPrefix(line, "data:") {
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data:")), &connection); err != nil {
				t.Fatal(err)
			}
			break
		}
	}
	if connection.ClientID == "" {
		t.Fatalf("no realtime connection: %v", scanner.Err())
	}
	req, err := http.NewRequest(http.MethodPost, server.URL+"/api/realtime", strings.NewReader(fmt.Sprintf(`{"clientId":%q,"subscriptions":["users/*"]}`, connection.ClientID)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", authToken(t, user))
	subscribed, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if err := subscribed.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if subscribed.StatusCode != http.StatusNoContent {
		t.Fatalf("subscription: %d", subscribed.StatusCode)
	}
	user.Set("name", "before expiry")
	save(t, app, user)
	var received bool
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), "before expiry") {
			received = true
			break
		}
	}
	if !received {
		t.Fatalf("active subscription did not receive data: %v", scanner.Err())
	}
	// Advance the session's age without a sleep or a real eight-hour wait.
	user.Set("sso_login_at", time.Now().Add(-9*time.Hour))
	user.Set("name", "after expiry")
	save(t, app, user)
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), "after expiry") {
			t.Fatal("expired subscription received protected data")
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("connection must close cleanly, not time out: %v", err)
	}
}

func TestMigrateKeepsTheProviderConfig(t *testing.T) {
	app := newApp(t, testConfig)
	configureProvider(t, app, claims())
	for range 2 {
		if err := Migrate(app, testConfig); err != nil {
			t.Fatal(err)
		}
	}
	users := usersCollection(t, app)
	if users.PasswordAuth.Enabled || users.OTP.Enabled || !users.OAuth2.Enabled || users.CreateRule == nil || *users.CreateRule != "@request.context = 'oauth2'" {
		t.Fatalf("incorrect auth configuration: %+v", users)
	}
	if _, ok := users.Fields.GetByName("sso_login_at").(*core.DateField); !ok {
		t.Fatal("login date field missing")
	}
	if provider, ok := users.OAuth2.GetProviderConfig("oidc"); !ok || provider.ClientId != "client" || provider.ClientSecret != "secret" || provider.Extra["jwksURL"] == nil {
		t.Fatalf("provider config lost: %+v", provider)
	}
}

type loggingApp struct {
	core.App
	logger *slog.Logger
}

func (app loggingApp) Logger() *slog.Logger { return app.logger }

func TestProviderWarnings(t *testing.T) {
	app := newApp(t, testConfig)
	config, err := testConfig.withDefaults()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		jwks     string
		issuers  []string
		userinfo string
		warn     bool
	}{
		{"missing both", "", nil, "", true},
		{"missing JWKS", "", []string{"https://issuer.test/"}, "", true},
		{"missing issuer", "https://issuer.test/jwks", nil, "", true},
		{"verified", "https://issuer.test/jwks", []string{"https://issuer.test/"}, "", false},
		{"userinfo", "", nil, "https://issuer.test/userinfo", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			users := usersCollection(t, app)
			users.OAuth2.Providers = []core.OAuth2ProviderConfig{{Name: "oidc", ClientId: "client", ClientSecret: "secret", AuthURL: "https://issuer.test/authorize", TokenURL: "https://issuer.test/token", UserInfoURL: tc.userinfo, Extra: map[string]any{"jwksURL": tc.jwks, "issuers": tc.issuers}}}
			save(t, app, users)
			var output bytes.Buffer
			warnIfTokensUnverified(loggingApp{App: app, logger: slog.New(slog.NewTextHandler(&output, nil))}, config)
			if warned := strings.Contains(output.String(), "verification is incomplete"); warned != tc.warn {
				t.Fatalf("warn=%v, want %v: %s", warned, tc.warn, output.String())
			}
		})
	}
}

func TestConfigNeedsGroupAndMaxAge(t *testing.T) {
	for _, config := range []Config{{SessionMaxAge: time.Hour}, {RequiredGroup: "g"}, {RequiredGroup: "g", SessionMaxAge: -time.Hour}} {
		if err := Register(nil, config); err == nil {
			t.Errorf("Register accepted invalid config: %+v", config)
		}
		if err := Migrate(nil, config); err == nil {
			t.Errorf("Migrate accepted invalid config: %+v", config)
		}
	}
}
