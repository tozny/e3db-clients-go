package authClient

import (
    "context"
    "os"
    "testing"
)

func TestNewReturnsE3DBAuthClientWithSpecifiedConfiguration(t *testing.T) {
    apiKey := "MyApiKey"
    apiSecret := "MyApiSecret"
    e3dbAuth := New(apiKey, apiSecret)
    if e3dbAuth.APIKey != apiKey {
        t.Errorf("Expected api key to be %s, got %+v", apiKey, e3dbAuth)
    }
    if e3dbAuth.APISecret != apiSecret {
        t.Errorf("Expected api secret to be %s, got %+v", apiSecret, e3dbAuth)
    }
}

// Apparently this variable is not evaluated unless called....
var setE3dbBaseURL = e3dbBaseURL

func TestGetTokenFailsWhenClientCredentialsAreBogus(t *testing.T) {
    e3dbAuth := New("FAKE", "FAKE")
    ctx := context.TODO()
    _, err := e3dbAuth.GetToken(ctx)
    if err == nil {
        t.Error("Expected error when calling GetToken with invalid auth client")
    }
}

func TestGetTokenSucceedsWhenClientCredentialsAreValid(t *testing.T) {
    e3dbAuth := New(os.Getenv("E3DB_API_KEY_ID"), os.Getenv("E3DB_API_KEY_SECRET"))
    ctx := context.TODO()
    token, err := e3dbAuth.GetToken(ctx)
    if err != nil {
        t.Error(err)
    }
}
