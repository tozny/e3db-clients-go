package e3dbClients

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// ClientConfig wraps configuration
// needed by an e3db client
type ClientConfig struct {
	Host      string // Hostname of the e3db API to communicate with
	APIKey    string // User/Client ID to use when communicating with the e3db API
	APISecret string // User/Client secret to use when communicating with the e3db API
	// Hostname for the soon to be deprecated (v1) e3db bearer auth service API.
	// Once request signing is the primary mode of authenticating e3db requests this can be removed.
	AuthNHost string
}

// E3DBHTTPAuthorizer implements the functionality needed to make
// an authenticated call to an e3db endpoint.
type E3DBHTTPAuthorizer interface {
	AuthHTTPClient(ctx context.Context) *http.Client
}

// RequestError provides additional details about the failed request.
type RequestError struct {
	message    string
	URL        string
	StatusCode int
}

// Error implements the error interface for RequestError.
func (err *RequestError) Error() string {
	return err.message
}

// NewError creates a new RequestError
func NewError(message, url string, statusCode int) *RequestError {
	return &RequestError{message, url, statusCode}
}

// FlatMapInternalError returns either a non nil internal error
// or nil error.
func FlatMapInternalError(internalError RequestError) error {
	var err error
	if internalError.StatusCode != 0 || internalError.Error() != "" {
		err = &internalError
	}
	return err
}

// MakeE3DBServiceCall attempts to call an e3db service by executing the provided request and deserializing the response into the provided result holder, returning error (if any).
func MakeE3DBServiceCall(httpAuthorizer E3DBHTTPAuthorizer, ctx context.Context, request *http.Request, result interface{}) *RequestError {
	client := httpAuthorizer.AuthHTTPClient(ctx)
	err := MakeRawServiceCall(client, request.WithContext(ctx), result)
	return &err
}

// MakeProxiedUserCall attempts to call an e3db service using provided user auth token to authenticate request.
func MakeProxiedUserCall(ctx context.Context, userAuthToken string, request *http.Request, result interface{}) RequestError {
	client := &http.Client{}
	request.Header.Add("Authorization", "Bearer "+userAuthToken)
	return MakeRawServiceCall(client, request, result)
}

// MakeRawServiceCall sends a request, auto decoding the response to the result interface if sent.
func MakeRawServiceCall(client *http.Client, request *http.Request, result interface{}) RequestError {
	response, err := client.Do(request)
	if err != nil {
		return RequestError{
			URL:     request.URL.String(),
			message: err.Error(),
		}
	}
	defer response.Body.Close()
	if !(response.StatusCode >= 200 && response.StatusCode <= 299) {
		requestURL := request.URL.String()
		return RequestError{
			StatusCode: response.StatusCode,
			URL:        requestURL,
			message:    fmt.Sprintf("e3db: %s: server http error %d", requestURL, response.StatusCode),
		}
	}
	// If no result is expected, don't attempt to decode a potentially
	// empty response stream and avoid incurring EOF errors
	if result == nil {
		return RequestError{}
	}
	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		return RequestError{
			URL:     request.URL.String(),
			message: err.Error(),
		}
	}
	return RequestError{}
}

// CreateRequest isolates duplicate code in creating http search request.
func CreateRequest(method string, path string, params interface{}) (*http.Request, *RequestError) {
	var buf bytes.Buffer
	var request *http.Request
	err := json.NewEncoder(&buf).Encode(&params)
	if err != nil {
		return request, &RequestError{
			URL:     path,
			message: err.Error(),
		}
	}
	request, err = http.NewRequest(method, path, &buf)
	if err != nil {
		return request, &RequestError{
			URL:     path,
			message: err.Error(),
		}
	}
	return request, nil
}
