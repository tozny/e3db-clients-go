package authClient

import (
	"context"
	"github.com/tozny/e3db-clients-go"
	"os"
	"testing"
)

var (
	e3dbAuthHost  = os.Getenv("E3DB_AUTH_SERVICE_HOST")
	e3dbAPIKey    = os.Getenv("E3DB_API_KEY_ID")
	e3dbAPISecret = os.Getenv("E3DB_API_KEY_SECRET")
)

func TestNewReturnsE3dbAuthClientWithSpecifiedConfiguration(t *testing.T) {
	config := e3dbClients.ClientConfig{
		APIKey:    "MyApiKey",
		APISecret: "MyApiSecret",
	}
	e3dbAuth := New(config)
	if e3dbAuth.APIKey != config.APIKey {
		t.Errorf("Expected api key to be %s, got %+v", config.APIKey, e3dbAuth)
	}
	if e3dbAuth.APISecret != config.APISecret {
		t.Errorf("Expected api secret to be %s, got %+v", config.APISecret, e3dbAuth)
	}
}

func TestGetTokenFailsWhenClientCredentialsAreBogus(t *testing.T) {
	config := e3dbClients.ClientConfig{
		APIKey:    "FAKE",
		APISecret: "FAKE",
		Host:      e3dbAuthHost,
		AuthNHost: e3dbAuthHost,
	}
	e3dbAuth := New(config)
	ctx := context.TODO()
	_, err := e3dbAuth.GetToken(ctx)
	if err == nil {
		t.Error("Expected error when calling GetToken with invalid auth client")
	}
}

func TestGetTokenSucceedsWhenClientCredentialsAreValid(t *testing.T) {
	config := e3dbClients.ClientConfig{
		APIKey:    e3dbAPIKey,
		APISecret: e3dbAPISecret,
		Host:      e3dbAuthHost,
		AuthNHost: e3dbAuthHost,
	}
	e3dbAuth := New(config)
	ctx := context.TODO()
	_, err := e3dbAuth.GetToken(ctx)
	if err != nil {
		t.Error(err)
	}
}

var e3dbClientId = os.Getenv("E3DB_CLIENT_ID")

func TestValidateTokenReturnsValidResultsForValidToken(t *testing.T) {
	config := e3dbClients.ClientConfig{
		APIKey:    e3dbAPIKey,
		APISecret: e3dbAPISecret,
		Host:      e3dbAuthHost,
		AuthNHost: e3dbAuthHost,
	}
	e3dbAuth := New(config)
	ctx := context.TODO()
	validToken, err := e3dbAuth.GetToken(ctx)
	if err != nil {
		t.Error(err)
	}
	validateTokenRequestParams := ValidateTokenRequest{Token: validToken.AccessToken}
	response, err := e3dbAuth.ValidateToken(ctx, validateTokenRequestParams)
	if err != nil {
		t.Errorf("Error: %s calling ValidateToken %+v", err, response)
	}
	if response.Valid != true {
		t.Errorf("Expected token %v to be valid, got %v", validToken, response)
	}
	if response.ClientId != e3dbClientId {
		t.Errorf("Expected token %v to belong to %v valid, got %v", validToken, e3dbClientId, response)

	}
}

func TestValidateTokenReturnsValidResultsForInvalidToken(t *testing.T) {
	config := e3dbClients.ClientConfig{
		APIKey:    e3dbAPIKey,
		APISecret: e3dbAPISecret,
		Host:      e3dbAuthHost,
		AuthNHost: e3dbAuthHost,
	}
	e3dbAuth := New(config)
	ctx := context.TODO()
	validateTokenRequestParams := ValidateTokenRequest{Token: "invalidToken.AccessToken"}
	_, err := e3dbAuth.ValidateToken(ctx, validateTokenRequestParams)
	if err == nil {
		t.Fatal("No error returned when validating invalid token")
	}
}
