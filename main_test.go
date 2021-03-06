package e3dbClients_test

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"testing"

	"github.com/google/uuid"
	e3dbClients "github.com/tozny/e3db-clients-go"
	"github.com/tozny/e3db-clients-go/accountClient"
	"github.com/tozny/e3db-clients-go/authClient"
	"github.com/tozny/e3db-clients-go/pdsClient"
	"github.com/tozny/e3db-clients-go/request"
	"github.com/tozny/e3db-clients-go/test"
	"github.com/tozny/utils-go/logging"
)

var (
	e3dbPDSHost          = os.Getenv("E3DB_STORAGE_SERVICE_HOST")
	e3dbClientHost       = os.Getenv("E3DB_CLIENT_SERVICE_HOST")
	e3dbAuthHost         = os.Getenv("E3DB_AUTH_SERVICE_HOST")
	e3dbAPIKey           = os.Getenv("E3DB_API_KEY_ID")
	e3dbAPISecret        = os.Getenv("E3DB_API_KEY_SECRET")
	e3dbAccountHost      = os.Getenv("E3DB_ACCOUNT_SERVICE_HOST")
	ValidPDSClientConfig = e3dbClients.ClientConfig{
		APIKey:    e3dbAPIKey,
		APISecret: e3dbAPISecret,
		Host:      e3dbPDSHost,
		AuthNHost: e3dbAuthHost,
	}
	ValidBootAccountClientConfig = e3dbClients.ClientConfig{
		APIKey:    e3dbAPIKey,
		APISecret: e3dbAPISecret,

		Host:      e3dbAccountHost,
		AuthNHost: e3dbAuthHost,
	}
	bootAccountClient         = accountClient.New(ValidBootAccountClientConfig)
	validPDSRegistrationToken string
	defaultPDSUserRecordType  = "integration_tests"
	validPDSUser              pdsClient.E3dbPDSClient
	validPDSUserConfig        e3dbClients.ClientConfig
	validPDSUserID            string
)

//TestMain gives all tests access to a client "validPDSUser" who is authorized to write to a default record type.
func TestMain(m *testing.M) {
	err := setup()
	if err != nil {
		fmt.Printf("Could perform setup for tests due to %s", err)
		os.Exit(1)
	}
	code := m.Run()
	os.Exit(code)
}

func setup() error {
	accountTag := uuid.New().String()
	queenAccountConfig, createAccountResp, err := test.MakeE3DBAccount(&testing.T{}, &bootAccountClient, accountTag, e3dbAuthHost)
	if err != nil {
		return err
	}
	queenAccountClient := accountClient.New(queenAccountConfig)
	accountServiceJWT := createAccountResp.AccountServiceToken

	queenAccountConfig.Host = e3dbPDSHost
	validPDSUser = pdsClient.New(queenAccountConfig)
	validPDSUserID = createAccountResp.Account.Client.ClientID
	validPDSUserConfig = queenAccountConfig
	validPDSRegistrationToken, err = test.CreateRegistrationToken(&queenAccountClient, accountServiceJWT)
	return err
}

func TestValidateTokenReturnsValidResultsForValidExternalClientToken(t *testing.T) {
	bootAuthConfig := e3dbClients.ClientConfig{
		APIKey:    e3dbAPIKey,
		APISecret: e3dbAPISecret,
		AuthNHost: e3dbAuthHost,
	}
	bootAuthClient := authClient.New(bootAuthConfig)
	validPDSUserConfig.Host = e3dbAuthHost
	externalClientAuthClient := authClient.New(validPDSUserConfig)

	ctx := context.Background()
	userToken, err := externalClientAuthClient.GetToken(ctx)
	if err != nil {
		t.Errorf("Error: %v fetching token for user %v", err, externalClientAuthClient)
	}
	validateTokenRequestParams := authClient.ValidateTokenRequest{Token: userToken.AccessToken, Internal: false}
	response, err := bootAuthClient.ValidateToken(ctx, validateTokenRequestParams)
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

func TestInterceptorsRun(t *testing.T) {
	before := false
	after := false
	interceptor := request.InterceptorFunc(func(r request.Requester, h *http.Request) (*http.Response, error) {
		before = true
		resp, err := r.Do(h)
		after = true
		return resp, err
	})
	config := e3dbClients.ClientConfig{
		APIKey:       e3dbAPIKey,
		APISecret:    e3dbAPISecret,
		Host:         e3dbPDSHost,
		AuthNHost:    e3dbAuthHost,
		Interceptors: []request.Interceptor{interceptor},
	}
	client := pdsClient.New(config)
	err := client.HealthCheck(context.Background())
	if err != nil {
		t.Errorf("%s health check failed using %+v\n", err, client)
	}
	if !before {
		t.Error("Expected to see code before the request run,  but before was false.")
	}
	if !after {
		t.Error("Expected to see code after the request run,  but after was false.")
	}
}

func TestLoggingInterceptor(t *testing.T) {
	var log bytes.Buffer
	logger := logging.NewServiceLogger(&log, "tester", "DEBUG")
	interceptor := request.LoggingInterceptor(&logger)
	config := e3dbClients.ClientConfig{
		APIKey:       e3dbAPIKey,
		APISecret:    e3dbAPISecret,
		Host:         e3dbPDSHost,
		AuthNHost:    e3dbAuthHost,
		Interceptors: []request.Interceptor{interceptor},
	}
	client := pdsClient.New(config)
	err := client.HealthCheck(context.Background())
	if err != nil {
		t.Errorf("%s health check failed using %+v\n", err, client)
	}
	logBytes := log.Bytes()
	matched, err := regexp.Match(`: DEBUG: tester: GET request to https?://[^/]+/v1/storage/servicecheck at .+? took .+?`, logBytes)
	if err != nil {
		t.Fatalf("could not validate log: %+v", err)
	}
	if !matched {
		t.Errorf("log format did not match expected. Got %q", logBytes)
	}
}
