package storageClient_test

import (
	"os"
	"testing"

	"github.com/google/uuid"
	e3dbClients "github.com/tozny/e3db-clients-go"
	"github.com/tozny/e3db-clients-go/accountClient"
	storageClientV2 "github.com/tozny/e3db-clients-go/storageClient"
	"github.com/tozny/e3db-clients-go/test"
)

var (
	internalToznyCyclopsHost                  = os.Getenv("TOZNY_CYCLOPS_SERVICE_HOST")
	internalE3dbAuthHost                      = os.Getenv("E3DB_AUTH_SERVICE_HOST")
	internalE3dbAccountHost                   = os.Getenv("E3DB_ACCOUNT_SERVICE_HOST")
	internalE3dbAPIKey                        = os.Getenv("E3DB_API_KEY_ID")
	internalE3dbAPISecret                     = os.Getenv("E3DB_API_KEY_SECRET")
	internalE3dbClientID                      = os.Getenv("E3DB_CLIENT_ID")
	InternalInternalBootstrapPublicSigningKey = os.Getenv("BOOTSTRAP_CLIENT_PUBLIC_SIGNING_KEY")
	InternalBootstrapPrivateSigningKey        = os.Getenv("BOOTSTRAP_CLIENT_PRIVATE_SIGNING_KEY")
	InternalValidAccountClientConfig          = e3dbClients.ClientConfig{
		APIKey:    internalE3dbAPIKey,
		APISecret: internalE3dbAPISecret,
		Host:      internalE3dbAccountHost,
		AuthNHost: internalE3dbAuthHost,
	}
	internalE3dbIdentityHost         = internalToznyCyclopsHost
	InternalBootIdentityClientConfig = e3dbClients.ClientConfig{
		ClientID:  internalE3dbClientID,
		APIKey:    internalE3dbAPIKey,
		APISecret: internalE3dbAPISecret,
		Host:      internalE3dbIdentityHost,
		AuthNHost: internalE3dbAuthHost,
		SigningKeys: e3dbClients.SigningKeys{
			Public: e3dbClients.Key{
				Type:     e3dbClients.DefaultSigningKeyType,
				Material: InternalInternalBootstrapPublicSigningKey,
			},
			Private: e3dbClients.Key{
				Type:     e3dbClients.DefaultSigningKeyType,
				Material: InternalBootstrapPrivateSigningKey,
			},
		},
	}
	InternalBootstrapClient = storageClientV2.New(InternalBootIdentityClientConfig)
)

func TestInternalGetNoteInfo(t *testing.T) {
	registrationClient := accountClient.New(e3dbClients.ClientConfig{Host: cyclopsServiceHost})
	queenClientConfig, _, err := test.MakeE3DBAccount(t, &registrationClient, uuid.New().String(), cyclopsServiceHost)
	if err != nil {
		t.Fatalf("Could not register account %s\n", err)
	}
	client := storageClientV2.New(queenClientConfig)
	if err != nil {
		t.Fatalf("Could not parse client ID. clientID: %s, err: %s", client.ClientID, err)
	}
	queenStorage := storageClientV2.New(queenClientConfig)
	data := make(map[string]string)
	data["test"] = "values"

	generatedNote, err := generateNote(queenClientConfig.SigningKeys.Public.Material, queenClientConfig)
	if err != nil {
		t.Fatalf("Failed to generate new note %+v", err)
	}

	noteName := "name" + uuid.New().String()
	generatedNote.IDString = noteName

	writtenNote, err := queenStorage.WriteNote(testCtx, *generatedNote)
	if err != nil {
		t.Fatalf("Failed to write new generatedNote %+v", err)
	}

	noteInfo, err := InternalBootstrapClient.InternalGetNoteInfo(testCtx, writtenNote.IDString)
	if err != nil {
		t.Fatalf("An error occurred during internal read note info. Error: %v", err)
	}

	if noteInfo.PublicRecipientSigningKey != writtenNote.RecipientSigningKey {
		t.Fatalf("Expected recipient signing keys to be the same.")
	}
}
