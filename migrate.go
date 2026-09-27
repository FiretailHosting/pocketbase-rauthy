package rauthy

import (
	"github.com/pocketbase/pocketbase/core"
)

// Migrate switches the auth collection to Rauthy-only sign-in: password and
// OTP sign-in off, OAuth2 on, account creation through OAuth2 or by superusers,
// and a field recording the last sign-in. Call it from one of the app's migrations.
//
// The provider list is left alone: the client ID and secret are entered in
// the PocketBase dashboard, and a migration must never overwrite them.
func Migrate(app core.App, config Config) error {
	config, err := config.withDefaults()
	if err != nil {
		return err
	}

	collection, err := app.FindCollectionByNameOrId(config.Collection)
	if err != nil {
		return err
	}

	// The OAuth2 context is assigned by PocketBase, not by the client.
	rule := "@request.context = 'oauth2'"
	collection.CreateRule = &rule
	collection.PasswordAuth.Enabled = false
	collection.OTP.Enabled = false
	collection.OAuth2.Enabled = true

	if collection.Fields.GetByName(config.LoginField) == nil {
		collection.Fields.Add(&core.DateField{Name: config.LoginField})
	}

	return app.Save(collection)
}
