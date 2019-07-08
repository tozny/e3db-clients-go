package billingclient

import (
	"context"

	"github.com/google/uuid"
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
	path := b.Host + "/internal/" + BillingServiceBasePath + "/create-customer"
	request, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return result, e3dbClients.NewError(err.Error(), path, 0)
	}
	err = e3dbClients.MakeE3DBServiceCall(b.E3dbAuthClient, ctx, request, &result)
	return result, err
}

func (b *E3dbBillingClient) InternalSubscriptionInfo(ctx context.Context, accountID uuid.UUID) (*InternalGetMeteredSubscriptionInfoResponse, error) {
	var result *InternalGetMeteredSubscriptionInfoResponse
	path := b.Host + "/internal/" + BillingServiceBasePath + "/subscription-info/" + accountID.String()
	request, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return result, e3dbClients.NewError(err.Error(), path, 0)
	}
	err = e3dbClients.MakeE3DBServiceCall(b.E3dbAuthClient, ctx, request, &result)
	return result, err
}

func (b *E3dbBillingClient) InternalSubscriptionStatus(ctx context.Context, accountID uuid.UUID) (*GetAccountStatusResponse, error) {
	var result *GetAccountStatusResponse
	path := b.Host + "/internal/" + BillingServiceBasePath + "/subscription/status/" + accountID.String()
	request, err := e3dbClients.CreateRequest("GET", path, accountID)
	if err != nil {
		return result, e3dbClients.NewError(err.Error(), path, 0)
	}
	err = e3dbClients.MakeE3DBServiceCall(b.E3dbAuthClient, ctx, request, &result)
	return result, err
}

func (b *E3dbBillingClient) AccountSubscriptionStatus(ctx context.Context) (*GetAccountStatusResponse, error) {
	var result *GetAccountStatusResponse
	path := b.Host + "/" + BillingServiceBasePath + "/subscription/status"
	request, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return result, e3dbClients.NewError(err.Error(), path, 0)
	}
	err = e3dbClients.MakeE3DBServiceCall(b.E3dbAuthClient, ctx, request, &result)
	return result, err
}

func (b *E3dbBillingClient) Unsubscribe(ctx context.Context) (*GetAccountStatusResponse, error) {
	var result *GetAccountStatusResponse
	path := b.Host + "/" + BillingServiceBasePath + "/unsubscribe"
	request, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return result, e3dbClients.NewError(err.Error(), path, 0)
	}
	err = e3dbClients.MakeE3DBServiceCall(b.E3dbAuthClient, ctx, request, &result)
	return result, err
}

func (b *E3dbBillingClient) Resubscribe(ctx context.Context) (*GetAccountStatusResponse, error) {
	var result *GetAccountStatusResponse
	path := b.Host + "/" + BillingServiceBasePath + "/resubscribe"
	request, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return result, e3dbClients.NewError(err.Error(), path, 0)
	}
	err = e3dbClients.MakeE3DBServiceCall(b.E3dbAuthClient, ctx, request, &result)
	return result, err
}

func (b *E3dbBillingClient) ListInvoices(ctx context.Context) (*ListInvoicesResponse, error) {
	var result *ListInvoicesResponse
	path := b.Host + "/" + BillingServiceBasePath + "/invoices"
	request, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return result, e3dbClients.NewError(err.Error(), path, 0)
	}
	err = e3dbClients.MakeE3DBServiceCall(b.E3dbAuthClient, ctx, request, &result)
	return result, err
}

func (b *E3dbBillingClient) UpdatePaymentSource(ctx context.Context, source UpdateSourceRequest) error {
	path := b.Host + "/" + BillingServiceBasePath + "/payment-source"
	request, err := e3dbClients.CreateRequest("POST", path, source)
	if err != nil {
		return e3dbClients.NewError(err.Error(), path, 0)
	}
	err = e3dbClients.MakeE3DBServiceCall(b.E3dbAuthClient, ctx, request, nil)
	return err
}

func (b *E3dbBillingClient) ApplyCoupon(ctx context.Context, coupon ApplyCouponRequest) error {
	path := b.Host + "/" + BillingServiceBasePath + "/coupon"
	request, err := e3dbClients.CreateRequest("POST", path, coupon)
	if err != nil {
		return e3dbClients.NewError(err.Error(), path, 0)
	}
	err = e3dbClients.MakeE3DBServiceCall(b.E3dbAuthClient, ctx, request, nil)
	return err
}

func (c *E3dbBillingClient) HealthCheck(ctx context.Context) error {
	path := c.Host + "/" + BillingServiceBasePath + "/healthcheck"
	request, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return err
	}
	err = e3dbClients.MakeE3DBServiceCall(c.E3dbAuthClient, ctx, request, nil)
	return err
}

func (c *E3dbBillingClient) ServiceCheck(ctx context.Context) error {
	path := c.Host + "/" + BillingServiceBasePath + "/servicecheck"
	request, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return err
	}
	err = e3dbClients.MakeE3DBServiceCall(c.E3dbAuthClient, ctx, request, nil)
	return err
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
