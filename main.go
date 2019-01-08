package e3dbClients

import (
    "context"
    "encoding/json"
    "fmt"
    "net/http"
)

// ClientConfig wraps configuration
// needed by an e3db client
type ClientConfig struct {
    Host      string //Hostname of the e3db API to communicate with
    APIKey    string //User/Client ID to use when communicating with the e3db API
    APISecret string //User/Client secret to use when communicating with the e3db API
}

// E3DBHTTPAuthorizer implements the functionality needed to make
// an authenticated call to an e3db endpoint.
type E3DBHTTPAuthorizer interface {
    AuthHTTPClient(ctx context.Context) *http.Client
}

// HTTPError wraps details of an HTTP error
type HTTPError struct {
    message    string
    URL        string
    StatusCode int
}

// Error implements the error interface for HTTPError.
func (err *HTTPError) Error() string {
    return err.message
}

// MakeE3DBServiceCall attempts to call an e3db service by executing the provided request and deserializing the response into the provided result holder, returning error (if any).
func MakeE3DBServiceCall(httpAuthorizer E3DBHTTPAuthorizer, ctx context.Context, request *http.Request, result interface{}) error {
    client := httpAuthorizer.AuthHTTPClient(ctx)
    response, err := client.Do(request)
    if err != nil {
        return err
    }
    defer response.Body.Close()
    if !(response.StatusCode >= 200 && response.StatusCode <= 299) {
        requestURL := request.URL.String()
        return &HTTPError{
            StatusCode: response.StatusCode,
            URL:        requestURL,
            message:    fmt.Sprintf("e3db: %s: server http error %d", requestURL, response.StatusCode),
        }
    }
    err = json.NewDecoder(response.Body).Decode(&result)
    return err
}
