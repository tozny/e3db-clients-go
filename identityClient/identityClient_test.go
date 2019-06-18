package identityClient

import (
	"context"
	"os"
	"testing"

	e3dbClients "github.com/tozny/e3db-clients-go"
)

var (
	e3dbIdentityHost          = os.Getenv("E3DB_IDENTITY_SERVICE_HOST")
	ValidIdentityClientConfig = e3dbClients.ClientConfig{
		Host: e3dbIdentityHost,
	}
	identityServiceClient = New(ValidIdentityClientConfig)
	testContext           = context.TODO()
)

func TestHealthCheckPassesIfServiceIsRunning(t *testing.T) {
	err := identityServiceClient.HealthCheck(testContext)
	if err != nil {
		t.Errorf("%s health check failed using %+v\n", err, identityServiceClient)
	}
}

func TestServiceCheckPassesIfServiceIsRunning(t *testing.T) {
	err := identityServiceClient.ServiceCheck(testContext)
	if err != nil {
		t.Errorf("%s service check failed using %+v\n", err, identityServiceClient)
	}
}
