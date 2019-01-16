package e3dbClients_test

import (
    "context"
    "fmt"
    "github.com/tozny/e3db-clients-go"
    "github.com/tozny/e3db-clients-go/authClient"
    "github.com/tozny/e3db-clients-go/pdsClient"
    "github.com/tozny/e3db-go/v2"
    "os"
    "testing"
    "time"
)

var e3dbBaseURL = os.Getenv("E3DB_API_URL")
var e3dbAPIKey = os.Getenv("E3DB_API_KEY_ID")
var e3dbAPISecret = os.Getenv("E3DB_API_KEY_SECRET")

var ValidClientConfig = e3dbClients.ClientConfig{
    APIKey:    e3dbAPIKey,
    APISecret: e3dbAPISecret,
    Host:      e3dbBaseURL,
}

func RegisterClient(email string) (pdsClient.E3dbPDSClient, authClient.E3dbAuthClient, string, error) {
    var user pdsClient.E3dbPDSClient
    var auth authClient.E3dbAuthClient
    e3dbPDS := pdsClient.New(ValidClientConfig)
    publicKey, privateKey, err := e3db.GenerateKeyPair()
    if err != nil {
        return user, auth, "", err
    }
    params := pdsClient.RegisterClientRequest{
        Email:      email,
        PublicKey:  pdsClient.ClientKey{Curve25519: publicKey},
        PrivateKey: pdsClient.ClientKey{Curve25519: privateKey},
    }
    ctx := context.TODO()
    resp, err := e3dbPDS.InternalRegisterClient(ctx, params)
    if err != nil {
        return user, auth, "", err
    }
    user = pdsClient.New(e3dbClients.ClientConfig{
        APIKey:    resp.APIKeyID,
        APISecret: resp.APISecret,
        Host:      e3dbBaseURL,
    })
    auth = authClient.New(e3dbClients.ClientConfig{
        APIKey:    resp.APIKeyID,
        APISecret: resp.APISecret,
        Host:      e3dbBaseURL,
    })
    return user, auth, resp.ClientID, err
}

var validPDSUser, validPDSAuthClient, validPDSUserID, _ = RegisterClient(fmt.Sprintf("test+main+%d@tozny.com", time.Now().Unix()))

func TestValidateTokenReturnsValidResultsForValidExternalClientToken(t *testing.T) {
    config := e3dbClients.ClientConfig{
        APIKey:    e3dbAPIKey,
        APISecret: e3dbAPISecret,
        Host:      e3dbBaseURL,
    }
    e3dbAuth := authClient.New(config)
    ctx := context.TODO()
    userToken, err := validPDSAuthClient.GetToken(ctx)
    if err != nil {
        t.Errorf("Error: %v fetching token for user %v", err, validPDSAuthClient)
    }
    validateTokenRequestParams := authClient.ValidateTokenRequest{Token: userToken.AccessToken, Internal: true}
    response, err := e3dbAuth.ValidateToken(ctx, validateTokenRequestParams)
    if err != nil {
        t.Errorf("Error: %s calling ValidateToken", err)
    }
    if response.Valid != true {
        t.Errorf("Expected token to be valid, got %+v", response)
    }
    if response.ClientId != validPDSUserID {
        t.Errorf("Expected token to belong to %v valid, got %+v", validPDSUserID, response)

    }
}
