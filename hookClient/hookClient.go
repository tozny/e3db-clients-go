package hookClient

import (
	"context"
	"fmt"
	"github.com/tozny/e3db-clients-go"
	"github.com/tozny/e3db-clients-go/authClient"
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
}

// CreateHook creates a hook that will fire for any of the provided enabled triggers,
// returning the created hook and error (if any).
func (c *E3dbHookClient) CreateHook(ctx context.Context, params CreateHookRequest) (*CreateHookResponse, error) {
	var createHookResponse *CreateHookResponse
	path := c.Host + HookServiceBasePath
	request, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return createHookResponse, err
	}
	internalError := e3dbClients.MakeE3DBServiceCall(c.E3dbAuthClient, ctx, request, &createHookResponse)
	return createHookResponse, e3dbClients.FlatMapInternalError(*internalError)
}

// ListHooks lists all hooks for the calling clients account,
// returning the listed hooks and error (if any).
func (c *E3dbHookClient) ListHooks(ctx context.Context) (*ListHooksResponse, error) {
	var listHooksResponse *ListHooksResponse
	path := c.Host + HookServiceBasePath
	request, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return listHooksResponse, err
	}
	internalError := e3dbClients.MakeE3DBServiceCall(c.E3dbAuthClient, ctx, request, &listHooksResponse)
	return listHooksResponse, e3dbClients.FlatMapInternalError(*internalError)
}

// DeleteHook deletes the hook with the given id, returning error (if any).
func (c *E3dbHookClient) DeleteHook(ctx context.Context, hookID int) error {
	path := c.Host + HookServiceBasePath + fmt.Sprintf("/%d", hookID)
	request, err := e3dbClients.CreateRequest("DELETE", path, nil)
	if err != nil {
		return err
	}
	internalError := e3dbClients.MakeE3DBServiceCall(c.E3dbAuthClient, ctx, request, nil)
	return e3dbClients.FlatMapInternalError(*internalError)
}

// New returns a new E3dbHookClient configured with the specified apiKey and apiSecret values.
func New(config e3dbClients.ClientConfig, hookHost string) E3dbHookClient {
	authService := authClient.New(config)
	return E3dbHookClient{
		config.APIKey,
		config.APISecret,
		hookHost,
		&authService,
	}
}
