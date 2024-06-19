package activityClient

import (
	"context"
	"os"
	"testing"

	e3dbClients "github.com/tozny/e3db-clients-go"
)

var (
	testContext          = context.TODO()
	toznyCyclopsHost     = os.Getenv("TOZNY_CYCLOPS_SERVICE_HOST")
	activityClientConfig = e3dbClients.ClientConfig{
		Host: toznyCyclopsHost,
	}
	anonymousActivityClient = New(activityClientConfig)
)

func TestHealthCheckPassesIfServiceIsRunning(t *testing.T) {
	err := anonymousActivityClient.HealthCheck(testContext)
	if err != nil {
		t.Errorf("%s health check failed using %+v\n", err, anonymousActivityClient)
	}
}

func TestServiceCheckPassesIfServiceIsRunning(t *testing.T) {
	err := anonymousActivityClient.ServiceCheck(testContext)
	if err != nil {
		t.Errorf("%s service check failed using %+v\n", err, anonymousActivityClient)
	}
}
