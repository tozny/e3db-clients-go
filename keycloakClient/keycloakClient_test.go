package keycloakClient

import (
	"testing"
	"time"

	"github.com/tozny/utils-go"
)

var (
	cyclopsServiceHost  = utils.MustGetenv("TOZNY_CYCLOPS_SERVICE_HOST")
	HTTPTimeout         = 10 * time.Second
	keycloakMasterRealm = utils.MustGetenv("KEYCLOAK_MASTER_REALM")
	keycloakUsername    = utils.MustGetenv("KEYCLOAK_USERNAME")
	keycloakPassword    = utils.MustGetenv("KEYCLOAK_PASSWORD")
)

// Verifies that calling getToken with the master realm succeeds
func TestGetTokenSucceedsWithValidClientCredentials(t *testing.T) {
	keycloakClientConfig := Config{
		AddrTokenProvider: cyclopsServiceHost,
		AddrAPI:           cyclopsServiceHost,
		Timeout:           HTTPTimeout,
	}
	kcClient, err := New(keycloakClientConfig)
	if err != nil {
		t.Fatalf("Failure creating keycloak client with err: %+v", err)
	}
	token, err := kcClient.GetToken(keycloakMasterRealm, keycloakUsername, keycloakPassword)
	if err != nil {
		t.Fatalf("Get token failed with err: %+v", err)
	}
	if token == "" {
		t.Fatal("Token must be nonempty.")
	}
}
