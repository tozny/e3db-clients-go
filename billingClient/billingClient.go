package billingclient

import (
	"context"
	"net/http"

	"github.com/google/uuid"
	e3dbClients "github.com/tozny/e3db-clients-go"
	"github.com/tozny/e3db-clients-go/authClient"
	"github.com/tozny/e3db-clients-go/request"
)

const (
	BillingServiceBasePath = "/v1/billing"
)

//E3dbBillingClient implements an http client for communication with an e3db billing service.
type E3dbBillingClient struct {
	APIKey    string
	APISecret string
	Host      string
	*authClient.E3dbAuthClient
	requester request.Requester
}

func (b *E3dbBillingClient) CreateAndSubscribeCustomer(ctx context.Context, params CreateCustomerRequest) (*CreateCustomerResponse, error) {
	var result *CreateCustomerResponse
	path := b.Host + "/internal" + BillingServiceBasePath + "/create-customer"
	req, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return result, e3dbClients.NewError(err.Error(), path, 0)
	}
	err = e3dbClients.MakeE3DBServiceCall(ctx, b.requester, b.E3dbAuthClient.TokenSource(), req, &result)
	return result, err
}

func (b *E3dbBillingClient) InternalSubscriptionInfo(ctx context.Context, accountID uuid.UUID) (*InternalGetMeteredSubscriptionInfoResponse, error) {
	var result *InternalGetMeteredSubscriptionInfoResponse
	path := b.Host + "/internal" + BillingServiceBasePath + "/subscription-info/" + accountID.String()
	req, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return result, e3dbClients.NewError(err.Error(), path, 0)
	}
	err = e3dbClients.MakeE3DBServiceCall(ctx, b.requester, b.E3dbAuthClient.TokenSource(), req, &result)
	return result, err
}

func (b *E3dbBillingClient) InternalSubscriptionStatus(ctx context.Context, accountID uuid.UUID) (*GetAccountStatusResponse, error) {
	var result *GetAccountStatusResponse
	path := b.Host + "/internal" + BillingServiceBasePath + "/subscription/status/" + accountID.String()
	req, err := e3dbClients.CreateRequest("GET", path, accountID)
	if err != nil {
		return result, e3dbClients.NewError(err.Error(), path, 0)
	}
	err = e3dbClients.MakeE3DBServiceCall(ctx, b.requester, b.E3dbAuthClient.TokenSource(), req, &result)
	return result, err
}

func (b *E3dbBillingClient) AccountSubscriptionStatus(ctx context.Context) (*GetAccountStatusResponse, error) {
	var result *GetAccountStatusResponse
	path := b.Host + BillingServiceBasePath + "/subscription/status"
	req, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return result, e3dbClients.NewError(err.Error(), path, 0)
	}
	err = e3dbClients.MakeE3DBServiceCall(ctx, b.requester, b.E3dbAuthClient.TokenSource(), req, &result)
	return result, err
}

func (b *E3dbBillingClient) Unsubscribe(ctx context.Context) (*GetAccountStatusResponse, error) {
	var result *GetAccountStatusResponse
	path := b.Host + BillingServiceBasePath + "/unsubscribe"
	req, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return result, e3dbClients.NewError(err.Error(), path, 0)
	}
	err = e3dbClients.MakeE3DBServiceCall(ctx, b.requester, b.E3dbAuthClient.TokenSource(), req, &result)
	return result, err
}

func (b *E3dbBillingClient) Resubscribe(ctx context.Context) (*GetAccountStatusResponse, error) {
	var result *GetAccountStatusResponse
	path := b.Host + BillingServiceBasePath + "/resubscribe"
	req, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return result, e3dbClients.NewError(err.Error(), path, 0)
	}
	err = e3dbClients.MakeE3DBServiceCall(ctx, b.requester, b.E3dbAuthClient.TokenSource(), req, &result)
	return result, err
}

func (b *E3dbBillingClient) ListInvoices(ctx context.Context) (*ListInvoicesResponse, error) {
	var result *ListInvoicesResponse
	path := b.Host + BillingServiceBasePath + "/invoices"
	req, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return result, e3dbClients.NewError(err.Error(), path, 0)
	}
	err = e3dbClients.MakeE3DBServiceCall(ctx, b.requester, b.E3dbAuthClient.TokenSource(), req, &result)
	return result, err
}

func (b *E3dbBillingClient) UpdatePaymentSource(ctx context.Context, source UpdateSourceRequest) error {
	path := b.Host + BillingServiceBasePath + "/payment-source"
	req, err := e3dbClients.CreateRequest("POST", path, source)
	if err != nil {
		return e3dbClients.NewError(err.Error(), path, 0)
	}
	err = e3dbClients.MakeE3DBServiceCall(ctx, b.requester, b.E3dbAuthClient.TokenSource(), req, nil)
	return err
}

func (b *E3dbBillingClient) ApplyCoupon(ctx context.Context, coupon ApplyCouponRequest) error {
	path := b.Host + BillingServiceBasePath + "/coupon"
	req, err := e3dbClients.CreateRequest("POST", path, coupon)
	if err != nil {
		return e3dbClients.NewError(err.Error(), path, 0)
	}
	err = e3dbClients.MakeE3DBServiceCall(ctx, b.requester, b.E3dbAuthClient.TokenSource(), req, nil)
	return err
}

func (c *E3dbBillingClient) HealthCheck(ctx context.Context) error {
	path := c.Host + BillingServiceBasePath + "/healthcheck"
	req, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return err
	}
	err = e3dbClients.MakeE3DBServiceCall(ctx, c.requester, c.E3dbAuthClient.TokenSource(), req, nil)
	return err
}

func (c *E3dbBillingClient) ServiceCheck(ctx context.Context) error {
	path := c.Host + BillingServiceBasePath + "/servicecheck"
	req, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return err
	}
	err = e3dbClients.MakeE3DBServiceCall(ctx, c.requester, c.E3dbAuthClient.TokenSource(), req, nil)
	return err
}

func New(config e3dbClients.ClientConfig) E3dbBillingClient {
	authService := authClient.New(config)
	return E3dbBillingClient{
		config.APIKey,
		config.APISecret,
		config.Host,
		&authService,
		request.ApplyInterceptors(&http.Client{}, config.Interceptors...),
	}
}
