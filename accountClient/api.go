package accountClient

import ()

// InternalGetClientAccountResponse represents a response
// from calling the Account /client endpoint
type InternalGetClientAccountResponse struct {
	AccountID string `json:"account_id"`
}
