package storageClient

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	e3dbClients "github.com/tozny/e3db-clients-go"
	"github.com/tozny/e3db-clients-go/accountClient"
	"github.com/tozny/e3db-clients-go/test"
)

var (
	cyclopsServiceHost = os.Getenv("TOZNY_CYCLOPS_SERVICE_HOST")
	testCtx            = context.Background()
)

func TestFullSignatureAuthenticationFlowSucceedsNoUID(t *testing.T) {
	// Make request through cyclops to test tozny header is parsed properly
	registrationClient := accountClient.New(e3dbClients.ClientConfig{Host: cyclopsServiceHost}) // empty account host to make registration request
	queenClientConfig, _, err := test.MakeE3DBAccount(t, &registrationClient, uuid.New().String(), cyclopsServiceHost)
	if err != nil {
		t.Fatalf("Could not register account %s\n", err)
	}
	queenClientConfig.Host = cyclopsServiceHost
	queenClientConfig.ClientID = "" // remove clientID
	storageServiceClient := New(queenClientConfig)
	noteToWrite, err := generateNote(queenClientConfig.SigningKeys.Public.Material, queenClientConfig)
	if err != nil {
		t.Fatalf("unable to generate note with config %+v\n", queenClientConfig)
	}
	_, err = storageServiceClient.WriteNote(testCtx, *noteToWrite)
	if err != nil {
		t.Errorf("unable to write note %+v, to storage service %s\n", noteToWrite, err)
	}
}

func TestFullSignatureAuthenticationFlowSucceedsWithUID(t *testing.T) {
	// Make request through cyclops to test tozny header is parsed properly
	registrationClient := accountClient.New(e3dbClients.ClientConfig{Host: cyclopsServiceHost}) // empty account host to make registration request
	queenClientConfig, _, err := test.MakeE3DBAccount(t, &registrationClient, uuid.New().String(), cyclopsServiceHost)
	if err != nil {
		t.Fatalf("Could not register account %s\n", err)
	}
	StorageClient := New(queenClientConfig)
	noteToWrite, err := generateNote(queenClientConfig.SigningKeys.Public.Material, queenClientConfig)
	if err != nil {
		t.Fatalf("unable to generate note with config %+v\n", queenClientConfig)
	}
	_, err = StorageClient.WriteNote(testCtx, *noteToWrite)
	if err != nil {
		t.Errorf("unable to write note %+v, to storage service %s\n", noteToWrite, err)
	}
}

func TestAddTozIDEACPWhenCreatingNote(t *testing.T) {
	// Make request through cyclops to test tozny header is parsed properly
	registrationClient := accountClient.New(e3dbClients.ClientConfig{Host: cyclopsServiceHost}) // empty account host to make registration request
	queenClientConfig, _, err := test.MakeE3DBAccount(t, &registrationClient, uuid.New().String(), cyclopsServiceHost)
	if err != nil {
		t.Fatalf("Could not register account %s\n", err)
	}
	StorageClient := New(queenClientConfig)
	noteToWrite, err := generateNote(queenClientConfig.SigningKeys.Public.Material, queenClientConfig)

	if err != nil {
		t.Fatalf("unable to generate note with config %+v\n", queenClientConfig)
	}
	noteToWrite.EACPS = &EACP{
		TozIDEACP: &TozIDEACP{
			RealmName: "someRealm",
		},
	}
	writtenNote, err := StorageClient.WriteNote(testCtx, *noteToWrite)
	if err != nil {
		t.Errorf("unable to write note with TozIDEACP %+v, to storage service %s\n ", noteToWrite, err)
	}
	if writtenNote.EACPS == nil || writtenNote.EACPS.TozIDEACP == nil {
		t.Fatalf("expected non nil TozIDEACP for note EACPS, got %+v", writtenNote.EACPS)
	}
}

func generateNote(recipientSigningKey string, clientConfig e3dbClients.ClientConfig) (*Note, error) {
	rawData := map[string]string{
		"key1": "rawnote",
		"key2": "unprocessednote",
		"key3": "organicnote",
	}
	ak := e3dbClients.RandomSymmetricKey()
	eak, err := e3dbClients.EncryptAccessKey(ak, clientConfig.EncryptionKeys)
	if err != nil {
		return nil, err
	}
	encryptedData := e3dbClients.EncryptData(rawData, ak)

	return &Note{
		Mode:                "Sodium",
		RecipientSigningKey: recipientSigningKey,
		WriterSigningKey:    clientConfig.SigningKeys.Public.Material,
		WriterEncryptionKey: clientConfig.EncryptionKeys.Public.Material,
		EncryptedAccessKey:  eak,
		Type:                "Integration Test",
		Data:                *encryptedData,
		Plain:               map[string]string{"extra1": "not encrypted", "extra2": "more plain data"},
		Signature:           "signed",
		MaxViews:            5,
	}, err
}
