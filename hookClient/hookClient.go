package hookClient

import (
	"context"
	"fmt"
	"net/http"

	e3dbClients "github.com/tozny/e3db-clients-go"
	"github.com/tozny/e3db-clients-go/authClient"
	"github.com/tozny/e3db-clients-go/request"
)

const (
	HookServiceBasePath = "/v1/hook" // HTTP PATH prefix for calls to the Hook service
)

// E3dbPDSClient implements an http client for communication with an e3db Hook service.
type E3dbHookClient struct {
	APIKey    string
	APISecret string
	Host      string
	*authClient.E3dbAuthClient
	requester request.Requester
}

// CreateHook creates a hook that will fire for any of the provided enabled triggers,
// returning the created hook and error (if any).
func (c *E3dbHookClient) CreateHook(ctx context.Context, params CreateHookRequest) (*CreateHookResponse, error) {
	var createHookResponse *CreateHookResponse
	path := c.Host + HookServiceBasePath
	req, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return createHookResponse, err
	}
	err = e3dbClients.MakeE3DBServiceCall(ctx, c.requester, c.E3dbAuthClient.TokenSource(), req, &createHookResponse)
	return createHookResponse, err
}

// ListHooks lists all hooks for the calling clients account,
// returning the listed hooks and error (if any).
func (c *E3dbHookClient) ListHooks(ctx context.Context) (*ListHooksResponse, error) {
	var listHooksResponse *ListHooksResponse
	path := c.Host + HookServiceBasePath
	req, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return listHooksResponse, err
	}
	err = e3dbClients.MakeE3DBServiceCall(ctx, c.requester, c.E3dbAuthClient.TokenSource(), req, &listHooksResponse)
	return listHooksResponse, err
}

// DeleteHook deletes the hook with the given id, returning error (if any).
func (c *E3dbHookClient) DeleteHook(ctx context.Context, hookID int) error {
	path := c.Host + HookServiceBasePath + fmt.Sprintf("/%d", hookID)
	req, err := e3dbClients.CreateRequest("DELETE", path, nil)
	if err != nil {
		return err
	}
	err = e3dbClients.MakeE3DBServiceCall(ctx, c.requester, c.E3dbAuthClient.TokenSource(), req, nil)
	return err
}

// New returns a new E3dbHookClient configured with the specified apiKey and apiSecret values.
func New(config e3dbClients.ClientConfig, hookHost string) E3dbHookClient {
	authService := authClient.New(config)
	return E3dbHookClient{
		config.APIKey,
		config.APISecret,
		hookHost,
		&authService,
		request.ApplyInterceptors(&http.Client{}, config.Interceptors...),
	}
}
