package e3dbClients

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/tozny/e3db-clients-go/request"
	"github.com/tozny/utils-go"
	"github.com/tozny/utils-go/logging"
	"github.com/tozny/utils-go/server"
	"golang.org/x/oauth2"
)

var (
	debugAPIResponse = utils.EnvOrDefault("DEBUG_API_RESPONSE", "false")
)

// ClientConfig wraps configuration
// needed by an e3db client
type ClientConfig struct {
	Host      string // Hostname of the e3db API to communicate with
	APIKey    string // User/Client ID to use when communicating with the e3db API
	APISecret string // User/Client secret to use when communicating with the e3db API
	ClientID  string // Serviced defined client uuid
	// Hostname for the soon to be deprecated (v1) e3db bearer auth service API.
	// Once request signing is the primary mode of authenticating e3db requests this can be removed.
	AuthNHost      string
	SigningKeys    SigningKeys           // AsymmetricEncryptionKeypair used for signing and authenticating requests
	EncryptionKeys EncryptionKeys        // AsymmetricEncryptionKeypair used for encrypting and decrypting data
	Interceptors   []request.Interceptor // Any number of request interceptors that will have access to the request as it is sent
}

// ToznyAuthNHeader wraps the structure used in the X-Tozny-Authn HTTP header
type ToznyAuthNHeader struct {
	Method    string          `json:"method"`
	AuthnInfo json.RawMessage `json:"authn_info"`
	User      json.RawMessage `json:"user"`
}

// ToznyAuthenticatedClientContext represents the contextual information provided by cyclops to downstream services
// when a user is successfully authenticated.
type ToznyAuthenticatedClientContext struct {
	ClientID       uuid.UUID            `json:"client_id"`
	AccountID      uuid.UUID            `json:"account_id"`
	Name           string               `json:"name"`
	EncryptionKeys PublicEncryptionKeys `json:"encryption_keys"`        // Tozny does not know a user's private encryption key
	SigningKeys    PublicSigningKeys    `json:"signing_keys,omitempty"` // Tozny does not know a user's private signing key
	Type           string               `json:"type"`
}

// RequestError provides additional details about the failed request.
type RequestError struct {
	message    string
	URL        string
	StatusCode int
}

// LoggingClient is used to log requests and timing based on configuration passed in
type LoggingClient struct {
	StandardClient http.Client
	logging.StructuredLogger
}

// Error implements the error interface for RequestError.
func (err *RequestError) Error() string {
	return err.message
}

// NewError creates a new RequestError
func NewError(message, url string, statusCode int) error {
	return &RequestError{message, url, statusCode}
}

// MakeE3DBServiceCall attempts to call an e3db service by executing the provided request and deserializing the response into the provided result holder, returning error (if any).
func MakeE3DBServiceCall(ctx context.Context, client request.Requester, source oauth2.TokenSource, req *http.Request, result interface{}) error {
	client = request.ApplyTokenInterceptor(source)(client)
	err := MakeRawServiceCall(client, req.WithContext(ctx), result)
	return err
}

// MakeSignedServiceCall makes a TSV1 signed request(using the private key from the provided keypair),
// deserializing the response into the provided result holder, and returning error (if any).
func MakeSignedServiceCall(ctx context.Context, client request.Requester, req *http.Request, keypair SigningKeys, signer string, result interface{}) error {
	privateSigningKey := keypair.Private.Material
	if privateSigningKey == "" {
		return ErrorPrivateSigningKeyRequired
	}
	publicSigningKey := keypair.Public.Material
	if publicSigningKey == "" {
		return ErrorPublicSigningKeyRequired
	}
	timestamp := time.Now().Unix()
	err := SignRequest(req, keypair, timestamp, signer)
	if err != nil {
		return err
	}
	err = MakeRawServiceCall(client, req.WithContext(ctx), result)
	return err
}

// MakeProxiedSignedCall attempts to call an e3db service using the provided
// signature to authenticate the request.
func MakeProxiedSignedCall(ctx context.Context, client request.Requester, headers http.Header, req *http.Request, result interface{}) error {
	req.Header.Add("Authorization", headers.Get("Authorization"))
	req.Header.Add(server.ToznyAuthNHeader, headers.Get(server.ToznyAuthNHeader))
	return MakeRawServiceCall(client, req, result)
}

// MakeProxiedUserCall attempts to call an e3db service using provided user auth token to authenticate request.
func MakeProxiedUserCall(ctx context.Context, client request.Requester, userAuthToken string, req *http.Request, result interface{}) error {
	req.Header.Add("Authorization", "Bearer "+userAuthToken)
	return MakeRawServiceCall(client, req, result)
}

// MakePublicCall makes an unauthenticated request to an e3db service.
func MakePublicCall(ctx context.Context, client request.Requester, req *http.Request, result interface{}) error {
	return MakeRawServiceCall(client, req, result)
}

// MakeRawServiceCall sends a request, auto decoding the response to the result interface if sent.
func MakeRawServiceCall(client request.Requester, req *http.Request, result interface{}) error {
	response, err := client.Do(req)
	if err != nil {
		return &RequestError{
			URL:     req.URL.String(),
			message: err.Error(),
		}
	}
	defer response.Body.Close()
	if !(response.StatusCode >= 200 && response.StatusCode <= 299) {
		requestURL := req.URL.String()
		return &RequestError{
			StatusCode: response.StatusCode,
			URL:        requestURL,
			message:    fmt.Sprintf("e3db: %s: server http error %d", requestURL, response.StatusCode),
		}
	}
	// If no result is expected, don't attempt to decode a potentially
	// empty response stream and avoid incurring EOF errors
	if result == nil {
		return nil
	}
	// Check if debug is on
	debugFlag, err := strconv.ParseBool(debugAPIResponse)
	if debugFlag {
		var bodyBytes []byte
		if response.Body != nil {
			bodyBytes, err = ioutil.ReadAll(response.Body)
			if err != nil {
				return &RequestError{
					URL:     req.URL.String(),
					message: err.Error(),
				}
			}
			fmt.Printf("Request Path %s \n Response Body %s \n  Response Status Code %d \n ", req.URL, string(bodyBytes), response.StatusCode)

		}
		// Repopulate body with the data read
		response.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))
	}
	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		return &RequestError{
			URL:     req.URL.String(),
			message: err.Error(),
		}
	}
	return nil
}

// TODO: determine a better way to handle X-args.

// ReturnE3dbServiceCall attempts to call an e3db service by executing the provided request and deserializing the response into the provided result holder, returning error (if any).
func ReturnE3dbServiceCall(ctx context.Context, client request.Requester, req *http.Request, result interface{}) (*http.Response, error) {
	resp, err := ReturnRawServiceCall(client, req.WithContext(ctx), result)
	return resp, err
}

// ReturnRawServiceCall sends a req, auto decoding the response to the result interface and returning Response.
func ReturnRawServiceCall(client request.Requester, req *http.Request, result interface{}) (*http.Response, error) {
	response, err := client.Do(req)
	if err != nil {
		return response, &RequestError{
			URL:     req.URL.String(),
			message: err.Error(),
		}
	}
	defer response.Body.Close()
	if !(response.StatusCode >= 200 && response.StatusCode <= 299) {
		requestURL := req.URL.String()
		return response, &RequestError{
			StatusCode: response.StatusCode,
			URL:        requestURL,
			message:    fmt.Sprintf("e3db: %s: server http error %d", requestURL, response.StatusCode),
		}
	}
	// If no result is expected, don't attempt to decode a potentially
	// empty response stream and avoid incurring EOF errors
	if result == nil {
		return response, nil
	}
	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		return response, &RequestError{
			URL:     req.URL.String(),
			message: err.Error(),
		}
	}
	return response, nil
}

// CreateRequest isolates duplicate code in creating http search request.
func CreateRequest(method string, path string, params interface{}) (*http.Request, error) {
	var buf bytes.Buffer
	var req *http.Request
	err := json.NewEncoder(&buf).Encode(&params)
	if err != nil {
		return req, err
	}
	req, err = http.NewRequest(method, path, &buf)
	if err != nil {
		return req, &RequestError{
			URL:     path,
			message: err.Error(),
		}
	}
	return req, nil
}

// XToznyAuthnRequestAuthenticator authenticates implements utils-go
// server.RequestAuthenticator to validate the presence and form of
// an X-TOZNY-AUTHN header and yield its clientID, if any
type XToznyAuthnRequestAuthenticator struct {
	AuthorizedClientIDs []string
}

// AuthenticateRequest validates the provided request authenticates
// an internal OR external e3db client via the request's X-TOZNY-AUTHN
// header, returning the clientID, authentication status of the
// provided req, and error (if any).
func (c *XToznyAuthnRequestAuthenticator) AuthenticateRequest(ctx context.Context, req *http.Request) (string, error) {
	var xTozAuthnValue ToznyAuthNHeader
	var toznyUser ToznyAuthenticatedClientContext
	xTozAuthnHeader := req.Header.Get(server.ToznyAuthNHeader)
	if xTozAuthnHeader == "" {
		return "", fmt.Errorf("unauthorized: No %s headers present", server.ToznyAuthNHeader)
	}
	err := json.Unmarshal([]byte(xTozAuthnHeader), &xTozAuthnValue)
	if err != nil {
		// If this gets hit the header is present, but in the completely overall format
		return "", fmt.Errorf("unauthorized: Invalid %s header, error during parsing: %s", server.ToznyAuthNHeader, err)
	}
	if xTozAuthnValue.User == nil || len(xTozAuthnValue.User) == 0 {
		// The header was correct and no user was present (a valid state for X-Tozny-Authn)
		return "", nil
	}
	err = json.Unmarshal(xTozAuthnValue.User, &toznyUser)
	if err != nil {
		// The header structure was correct but the user structure was not
		return "", fmt.Errorf("present but invalid %s header, error during parsing \"user\" field: %s", server.ToznyAuthNHeader, err)
	}
	for _, authorizedClientID := range c.AuthorizedClientIDs {
		if toznyUser.ClientID.String() == authorizedClientID {
			return authorizedClientID, nil
		}
	}
	return toznyUser.ClientID.String(), fmt.Errorf("unauthorized: client %s was not in list of authorized clients %+v", toznyUser.ClientID.String(), c.AuthorizedClientIDs)
}

// ExtractToznyAuthenticatedClientContext extracts a ToznyAuthenticatedClientContext from a header
func ExtractToznyAuthenticatedClientContext(header http.Header) (ToznyAuthenticatedClientContext, error) {
	var toznyAuthenticatedClientContext ToznyAuthenticatedClientContext
	var toznyAuthNHeader ToznyAuthNHeader

	potentialToznyAuthNHeader := header.Get(server.ToznyAuthNHeader)
	if potentialToznyAuthNHeader == "" {
		return toznyAuthenticatedClientContext, fmt.Errorf("authNHeader not present")
	}

	err := json.Unmarshal([]byte(potentialToznyAuthNHeader), &toznyAuthNHeader)
	if err != nil {
		return toznyAuthenticatedClientContext, fmt.Errorf("authNHeader is not properly formatted")
	}
	err = json.Unmarshal([]byte(toznyAuthNHeader.User), &toznyAuthenticatedClientContext)
	if err != nil {
		return toznyAuthenticatedClientContext, fmt.Errorf("authenticatedClientContext is not properly formatted")
	}
	return toznyAuthenticatedClientContext, err
}

// Do overrides the http Client method, as well as adds extra logging to requests
func (lc *LoggingClient) Do(req *http.Request) (*http.Response, error) {
	startTime := time.Now()
	at := req.Header.Get("Date")
	if at == "" {
		at = startTime.String()
	}
	resp, err := lc.Do(req)
	lengthOfRequest := time.Since(startTime)
	lc.Infof("%s request to %s at %s took %s", req.Method, req.URL, at, lengthOfRequest)
	return resp, err
}
