package metricClient

import (
	"time"
)

// APIAggregateRequest is used to make an Aggregate call.
type APIAggregateRequest struct {
	Range        QueryRange `json:"range"`         // Range is for the time the request was made to Tozny services
	IncludeEmpty bool       `json:"include_empty"` // Include dates with count of 0, defaults to false.
	AccountID    string     `json:"account_id"`
	ClientIDs    []string   `json:"client_ids"`
}

// APIAggregateResponse is returned from an Aggregate call.
type APIAggregateResponse struct {
	AccountID string         `json:"account_id"`
	Results   []APIAggregate `json:"results"`
}

// APIAggregate is a single aggregate returned from the Aggregate endpoint.
type APIAggregate struct {
	Date  time.Time `json:"date"`  // Date which aggregate corresponds to
	Count int64     `json:"count"` // Count of API request for the aggregation
}

// QueryRange contains the time range in which to query.
type QueryRange struct {
	Start time.Time `json:"start_time"`
	End   time.Time `json:"end_time"`
}

// APIMetricsRequest is the request object used for searching api metrics.
type APIMetricsRequest struct {
	NextToken   int         `json:"next_token"`   // Provided when paginating through query results
	Limit       int         `json:"limit"`        // The max number of results to return.
	ExcludeLogs bool        `json:"exclude_logs"` // Whether to return just counts of requests or the full request, defaults to false.
	AccountID   string      `json:"account_id"`   // AccountID that owns the relevant APIMetrics
	Match       QueryParams `json:"match"`        // Params to match on
	Exclude     QueryParams `json:"exclude"`      // Params to exclude on
	Range       QueryRange  `json:"range"`        // Range is for the time the request was made to Tozny services
}

// APIMetricsResponse is the response object for requests to the metrics search public api
type APIMetricsResponse struct {
	NextToken    int         `json:"next_token"`    // Value to use when paginating through query results
	TotalResults int64       `json:"total_results"` // Total number of metrics matching request, maximum ~10,000 if larger than 10,000 use smaller range
	Results      []APIMetric `json:"results"`       // Only returned if IncludeLogs is true for the corresponding request
}

// APIMetric is returned as a list by queries to the metrics search api
type APIMetric struct {
	AccountID  string    `json:"account_id"`
	ClientID   string    `json:"client_id"`
	Path       string    `json:"request_path"`
	Body       string    `json:"request_body"`
	Method     string    `json:"request_method"`
	StatusCode int       `json:"status_code"`
	Time       time.Time `json:"request_time"`
}

// ActiveUserAggregateRequest is used to make an ActiveUser aggregate call.
type ActiveUserAggregateRequest struct {
	Range            QueryRange `json:"range"`
	AccountID        string     `json:"account_id"`
	ClientType       string     `json:"client_type"`
	PaidRequestsOnly bool       `json:"paid_requests_only"` // set to false for all request types (paid and unpaid)
}

// ActiveUserAggregateResponse is the response of an ActiveUser aggregate call.
type ActiveUserAggregateResponse struct {
	AccountID   string `json:"account_id"`
	ActiveUsers int    `json:"active_users"`
}

// ApiEndpoint includes the path and method of a service call
type ApiEndpoint struct {
	Path   string `json:"path"`   // Path of the request, starting after the host
	Method string `json:"method"` // Method used i.e. GET | POST ...
}

// QueryParams that are the availalble fields to search for metrics on metrics can be searched on using the public api
type QueryParams struct {
	ClientIDs    []string      `json:"client_ids"`
	APIEndpoints []ApiEndpoint `json:"api_endpoints"`
	StatusCodes  []int         `json:"status_codes"`
}

type FileSizeMetric struct {
	ClientID string `json:"client_id"`
	Bytes    int64  `json:"bytes"`
}

type FileSizeMetricResponse struct {
	DocumentID string `json:"document_id"`
}
