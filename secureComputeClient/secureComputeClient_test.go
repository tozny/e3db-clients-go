package secureComputeClient

import (
	"context"
	"os"
	"testing"

	e3dbClients "github.com/tozny/e3db-clients-go"
)

var (
	testContext                           = context.TODO()
	toznyCyclopsHost                      = os.Getenv("TOZNY_CYCLOPS_SERVICE_HOST")
	serviceCheckSecureComputeClientConfig = e3dbClients.ClientConfig{
		Host: toznyCyclopsHost,
	}
	anonymouSecureComputeServiceClient = New(serviceCheckSecureComputeClientConfig)
)

func TestHealthCheckPassesIfServiceIsRunning(t *testing.T) {
	err := anonymouSecureComputeServiceClient.HealthCheck(testContext)
	if err != nil {
		t.Errorf("%s health check failed using %+v\n", err, anonymouSecureComputeServiceClient)
	}
}

func TestServiceCheckPassesIfServiceIsRunning(t *testing.T) {
	err := anonymouSecureComputeServiceClient.ServiceCheck(testContext)
	if err != nil {
		t.Errorf("%s service check failed using %+v\n", err, anonymouSecureComputeServiceClient)
	}
}
