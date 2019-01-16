package authClient

// ValidateTokenRequest represents a valid request to the auth service's /validate endpoint.
type ValidateTokenRequest struct {
    Token    string `json:"token"`    //The token to validate
    Internal bool   `json:"internal"` //Whether this token belongs to an internal client
}

// ValidateTokenRequest represents a response to calling auth service's /validate endpoint.
type ValidateTokenResponse struct {
    ClientId string `json:"client_id"` //The client associated with this token
    Valid    bool   `json:"valid"`     //Whether the token was valid
}
