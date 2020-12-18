package metricClient

import (
	"context"
	"net/http"

	e3dbClients "github.com/tozny/e3db-clients-go"
	"github.com/tozny/e3db-clients-go/authClient"
	"github.com/tozny/e3db-clients-go/request"
)

var (
	MetricServiceBasePath = "v1/metric/"
)

//MetricClient implements an http client for communication with the metrics service.
type MetricClient struct {
	APIKey    string
	APISecret string
	Host      string
	*authClient.E3dbAuthClient
	requester request.Requester
}

// Aggregations gets the requests aggregation from the metrics service.
func (c *MetricClient) Aggregations(ctx context.Context, params APIAggregateRequest) (*APIAggregateResponse, error) {
	var result *APIAggregateResponse
	path := c.Host + "/" + MetricServiceBasePath + "requests/aggregations"
	req, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeE3DBServiceCall(ctx, c.requester, c.E3dbAuthClient.TokenSource(), req, &result)
	return result, err
}

// RequestsMetrics queries elastic search for API Metrics matching params provided
func (c *MetricClient) RequestsMetrics(ctx context.Context, params APIMetricsRequest) (*APIMetricsResponse, error) {
	var result *APIMetricsResponse
	path := c.Host + "/" + MetricServiceBasePath + "requests"
	req, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeE3DBServiceCall(ctx, c.requester, c.E3dbAuthClient.TokenSource(), req, &result)
	return result, err
}

// ActiveUsers gets the active users for an account from the metrics service.
func (c *MetricClient) ActiveUsers(ctx context.Context, params ActiveUserAggregateRequest) (*ActiveUserAggregateResponse, error) {
	var result *ActiveUserAggregateResponse
	path := c.Host + "/" + MetricServiceBasePath + "requests/aggregations/active-users"
	req, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeE3DBServiceCall(ctx, c.requester, c.E3dbAuthClient.TokenSource(), req, &result)
	return result, err
}

// AddFileSizeMetric inserts a fileSizeMetric into the metrics service elastic search database.
func (c *MetricClient) AddFileSizeMetric(ctx context.Context, params FileSizeMetric) (FileSizeMetricResponse, error) {
	path := c.Host + "/" + MetricServiceBasePath + "requests/files"
	req, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return FileSizeMetricResponse{}, err
	}
	resp := FileSizeMetricResponse{}
	err = e3dbClients.MakeE3DBServiceCall(ctx, c.requester, c.E3dbAuthClient.TokenSource(), req, &resp)
	return resp, err
}

// New returns a new E3dbSearchIndexerClient for authenticated communication with a Search Indexer service at the specified endpoint.
func New(config e3dbClients.ClientConfig) MetricClient {
	authService := authClient.New(config)
	return MetricClient{
		config.APIKey,
		config.APISecret,
		config.Host,
		&authService,
		request.ApplyInterceptors(&http.Client{}, config.Interceptors...),
	}
}
