package billingclient

import (
	"context"

	e3dbClients "github.com/tozny/e3db-clients-go"
	"github.com/tozny/e3db-clients-go/authClient"
)

const (
	BillingServiceBasePath = "v1/billing"
)

//E3dbBillingClient implements an http client for communication with an e3db billing service.
type E3dbBillingClient struct {
	APIKey    string
	APISecret string
	Host      string
	*authClient.E3dbAuthClient
}

func (b *E3dbBillingClient) CreateAndSubscribeCustomer(ctx context.Context, params CreateCustomerRequest) (*CreateCustomerResponse, error) {
	var result *CreateCustomerResponse
	path := b.Host + "/internal/" + BillingServiceBasePath + "/create_customer"
	request, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return result, e3dbClients.NewError(err.Error(), path, 0)
	}
	err = e3dbClients.MakeE3DBServiceCall(b.E3dbAuthClient, ctx, request, &result)
	return result, err
}

func New(config e3dbClients.ClientConfig) E3dbBillingClient {
	authService := authClient.New(config)
	return E3dbBillingClient{
		config.APIKey,
		config.APISecret,
		config.Host,
		&authService,
	}
}
