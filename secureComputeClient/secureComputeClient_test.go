package secureComputeClient

import (
	"context"
	"errors"
	"net/http"
	"os"
	"testing"

	"github.com/google/uuid"
	e3dbClients "github.com/tozny/e3db-clients-go"
	"github.com/tozny/e3db-clients-go/accountClient"
	"github.com/tozny/e3db-clients-go/test"
)

var (
	testContext                           = context.TODO()
	toznyCyclopsHost                      = os.Getenv("TOZNY_CYCLOPS_SERVICE_HOST")
	serviceCheckSecureComputeClientConfig = e3dbClients.ClientConfig{
		Host: toznyCyclopsHost,
	}
	anonymouSecureComputeServiceClient = New(serviceCheckSecureComputeClientConfig)
	e3dbAuthHost                       = os.Getenv("E3DB_AUTH_SERVICE_HOST")
	e3dbAccountHost                    = os.Getenv("E3DB_ACCOUNT_SERVICE_HOST")
	e3dbAPIKey                         = os.Getenv("E3DB_API_KEY_ID")
	e3dbAPISecret                      = os.Getenv("E3DB_API_KEY_SECRET")
	e3dbClientID                       = os.Getenv("E3DB_CLIENT_ID")
	ValidAccountClientConfig           = e3dbClients.ClientConfig{
		APIKey:    e3dbAPIKey,
		APISecret: e3dbAPISecret,
		Host:      e3dbAccountHost,
		AuthNHost: e3dbAuthHost,
	}
	accountServiceClient = accountClient.New(ValidAccountClientConfig)
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

func getClientIDAndSecureClient(t *testing.T) (E3dbSecureComputeClient, uuid.UUID) {
	registrationClient := accountClient.New(e3dbClients.ClientConfig{Host: toznyCyclopsHost}) // empty account host to make registration request
	queenClientConfig, _, err := test.MakeE3DBAccount(t, &registrationClient, uuid.New().String(), toznyCyclopsHost)
	if err != nil {
		t.Fatalf("Could not register account %s\n", err)
	}

	queenClientConfig.Host = toznyCyclopsHost
	sc := New(queenClientConfig)
	queenClientID, err := uuid.Parse(queenClientConfig.ClientID)
	if err != nil {
		t.Fatalf("Returned queen client ID could not be parsed to a UUID")
	}
	return sc, queenClientID
}

// TestFetchAllComputationsEndpointReturnsSuccess fetches all computations that are available
func TestFetchAllComputationsEndpointReturnsSuccess(t *testing.T) {
	secureCompute, _ := getClientIDAndSecureClient(t)
	response, err := secureCompute.FetchAvailableComputations(testContext)
	if err != nil {
		t.Fatalf("Error %+v", err)
	}
	if len(response.Computations) == 0 {
		t.Fatalf("Error Expected one Computation %+v", response)
	}

}

// TestSubscribeEndpointReturnsSuccessWithNoManagers tests the path of subscription with no managers
func TestSubscribeEndpointReturnsSuccessWithNoManagers(t *testing.T) {
	secureCompute, queenID := getClientIDAndSecureClient(t)
	// Fetch available computation
	computation, err := secureCompute.FetchAvailableComputations(testContext)
	if err != nil {
		t.Fatalf("Error %+v", err)
	}
	if len(computation.Computations) <= 0 {
		t.Fatal("Error expected atleast one computation")
	}
	// SUbscribe to one
	params := SubscriptionRequest{
		ToznyClientID: queenID,
		ComputationID: computation.Computations[0].ComputationID,
	}
	_, err = secureCompute.Subscribe(testContext, params)
	if err != nil {
		t.Fatalf("Error %+v", err)
	}
}

// TestSubscribeEndpointReturnsSuccessWithManagers tests the path of subscription with managers
func TestSubscribeEndpointReturnsSuccessWithManagers(t *testing.T) {
	secureCompute, queenID := getClientIDAndSecureClient(t)
	// fetch available computation
	computation, err := secureCompute.FetchAvailableComputations(testContext)
	if err != nil {
		t.Fatalf("Error %+v", err)
	}
	if len(computation.Computations) <= 0 {
		t.Fatal("Error expected atleast one computation")
	}
	// Subscribe to one
	params := SubscriptionRequest{
		ToznyClientID: queenID,
		ComputationID: computation.Computations[0].ComputationID,
		SubscriptionManagers: []SubscriptionManagers{
			SubscriptionManagers{ToznyClientID: uuid.New()}},
	}
	_, err = secureCompute.Subscribe(testContext, params)
	if err != nil {
		t.Fatalf("Error %+v", err)
	}
}

// TestSubscribeEndpointForFakeComputation tests the path for an unknown computation
func TestSubscribeEndpointForFakeComputation(t *testing.T) {
	secureCompute, queenID := getClientIDAndSecureClient(t)

	// SUbscribe to one
	params := SubscriptionRequest{
		ToznyClientID: queenID,
		ComputationID: uuid.New(),
	}
	_, err := secureCompute.Subscribe(testContext, params)
	var tozError *e3dbClients.RequestError
	if errors.As(err, &tozError) {
		if tozError.StatusCode != http.StatusNotFound {
			t.Fatalf("Expected 404 error %s with fake subscription ", err)
		}
	} else {

		t.Fatalf("Expected 404 error %s with fake subscription ", err)
	}
}

// TestUpdateSubscribeEndpointReturnsSuccess test the path of updating a valid subscription
func TestUpdateSubscribeEndpointReturnsSuccess(t *testing.T) {
	secureCompute, queenID := getClientIDAndSecureClient(t)
	// Fetch available computation
	computation, err := secureCompute.FetchAvailableComputations(testContext)
	if err != nil {
		t.Fatalf("Error %+v", err)
	}
	if len(computation.Computations) <= 0 {
		t.Fatal("Error expected atleast one computation")
	}
	// Subscribe to one
	var manager []SubscriptionManagers
	manager = append(manager, SubscriptionManagers{ToznyClientID: uuid.New()})
	params := SubscriptionRequest{
		ToznyClientID:        queenID,
		ComputationID:        computation.Computations[0].ComputationID,
		SubscriptionManagers: manager,
	}
	subscription, err := secureCompute.Subscribe(testContext, params)
	if err != nil {
		t.Fatalf("Error %+v", err)
	}
	// Fetch sub
	params3 := FetchSubscriptionsRequest{
		ToznyClientID: queenID,
	}
	subResponse, err := secureCompute.FetchSubsciptions(testContext, params3)
	if err != nil {
		t.Fatalf("Error  %+v", err)
	}
	if len(subResponse.Computations[0].SubscriptionManagers) != 1 {
		t.Fatalf("Error Expected 1 Manager Got  %+v", subResponse)
	}
	// Update Subscription
	params2 := UpdateSubscriptionRequest{
		ComputationID:        subscription.ComputationID,
		SubscriptionManagers: []SubscriptionManagers{},
	}
	err = secureCompute.UpdateSubscription(testContext, params2)
	if err != nil {
		t.Fatalf("Error %+v", err)
	}

	subResponse, err = secureCompute.FetchSubsciptions(testContext, params3)
	if err != nil {
		t.Fatalf("Error %+v", err)
	}
	if len(subResponse.Computations[0].SubscriptionManagers) != 0 {
		t.Fatalf("Error Expected 0 Manager Got  %+v", subResponse)
	}

}

// TestUpdateSubscribeEndpointForFakeSubscription tests the path of updating an unknown subscription
func TestUpdateSubscribeEndpointForFakeSubscription(t *testing.T) {
	secureCompute, _ := getClientIDAndSecureClient(t)
	// Fetch available computation
	computation, err := secureCompute.FetchAvailableComputations(testContext)
	if err != nil {
		t.Fatalf("Error %+v", err)
	}
	if len(computation.Computations) <= 0 {
		t.Fatal("Error expected atleast one computation")
	}
	// Update Subscription
	params2 := UpdateSubscriptionRequest{
		ComputationID:        computation.Computations[0].ComputationID,
		SubscriptionManagers: []SubscriptionManagers{},
	}
	err = secureCompute.UpdateSubscription(testContext, params2)
	var tozError *e3dbClients.RequestError
	if errors.As(err, &tozError) {
		if tozError.StatusCode != http.StatusNotFound {
			t.Fatalf("Expected 404 error %s updating a fake subscription ", err)
		}
	} else {

		t.Fatalf("Expected 404 error %s updating a fake subscription ", err)
	}

}

// TestFetchSubscribeEndpointReturnsSuccess test the path of fetching subscriptions
func TestFetchSubscribeEndpointReturnsSuccess(t *testing.T) {
	secureCompute, queenID := getClientIDAndSecureClient(t)
	// Fetch available computation
	computation, err := secureCompute.FetchAvailableComputations(testContext)
	if err != nil {
		t.Fatalf("Error %+v", err)
	}
	if len(computation.Computations) <= 0 {
		t.Fatal("Error expected atleast one computation")
	}
	// Subscribe to one
	var manager []SubscriptionManagers
	manager = append(manager, SubscriptionManagers{ToznyClientID: uuid.New()})
	params := SubscriptionRequest{
		ToznyClientID:        queenID,
		ComputationID:        computation.Computations[0].ComputationID,
		SubscriptionManagers: manager,
	}
	_, err = secureCompute.Subscribe(testContext, params)
	if err != nil {
		t.Fatalf("Error %+v", err)
	}
	// Fetch sub
	params3 := FetchSubscriptionsRequest{
		ToznyClientID: queenID,
	}
	subResponse, err := secureCompute.FetchSubsciptions(testContext, params3)
	if err != nil {
		t.Fatalf("Error  %+v", err)
	}
	if len(subResponse.Computations[0].SubscriptionManagers) != 1 {
		t.Fatalf("Error Expected 1 Manager Got  %+v", subResponse)
	}

}

//T estFetchSubscribeEndpointWithNoSubscriptions tests the path of fetching all subscriptions when none exist
func TestFetchSubscribeEndpointWithNoSubscriptions(t *testing.T) {
	secureCompute, queenID := getClientIDAndSecureClient(t)
	params3 := FetchSubscriptionsRequest{
		ToznyClientID: queenID,
	}
	subResponse, err := secureCompute.FetchSubsciptions(testContext, params3)
	if err != nil {
		t.Fatalf("Error  %+v", err)
	}
	if len(subResponse.Computations) != 0 {
		t.Fatalf("Expected no computations, got %+v", subResponse)
	}

}

// TestUnsubscribeEndpointForFakeSubscription tests the path of unsubscribing to a unknown subscription
func TestUnsubscribeEndpointForFakeSubscription(t *testing.T) {
	secureCompute, queenID := getClientIDAndSecureClient(t)
	params := UnsubscribeRequest{
		ComputationID: uuid.New(),
		ToznyClientID: queenID,
	}
	err := secureCompute.Unsubscribe(testContext, params)
	if err != nil {
		t.Fatalf("Error %+v", err)
	}
}

// TestUnsubscribeEndpointReturnsSuccess test the path of unsubscribing to a valid subscription
func TestUnsubscribeEndpointReturnsSuccess(t *testing.T) {
	secureCompute, queenID := getClientIDAndSecureClient(t)
	// Fetch available computation
	computation, err := secureCompute.FetchAvailableComputations(testContext)
	if err != nil {
		t.Fatalf("Error %+v", err)
	}
	if len(computation.Computations) <= 0 {
		t.Fatal("Error expected atleast one computation")
	}
	// Subscribe to one
	var manager []SubscriptionManagers
	manager = append(manager, SubscriptionManagers{ToznyClientID: uuid.New()})
	params := SubscriptionRequest{
		ToznyClientID:        queenID,
		ComputationID:        computation.Computations[0].ComputationID,
		SubscriptionManagers: manager,
	}
	subscription, err := secureCompute.Subscribe(testContext, params)
	if err != nil {
		t.Fatalf("Error %+v", err)
	}
	// Fetch sub
	params3 := FetchSubscriptionsRequest{
		ToznyClientID: queenID,
	}
	subResponse, err := secureCompute.FetchSubsciptions(testContext, params3)
	if err != nil {
		t.Fatalf("Error  %+v", err)
	}
	if len(subResponse.Computations[0].SubscriptionManagers) != 1 {
		t.Fatalf("Error Expected 1 Manager Got  %+v", subResponse)
	}
	// Update Subscription
	params2 := UnsubscribeRequest{
		ComputationID: subscription.ComputationID,
		ToznyClientID: queenID,
	}
	err = secureCompute.Unsubscribe(testContext, params2)
	if err != nil {
		t.Fatalf("Error %+v", err)
	}
	subResponse, err = secureCompute.FetchSubsciptions(testContext, params3)
	if err != nil {
		t.Fatalf("Error %+v", err)
	}
	if len(subResponse.Computations) != 0 {
		t.Fatalf("Error Expected 0  Got  %+v", subResponse)
	}

}
