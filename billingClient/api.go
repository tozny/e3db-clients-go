package billingclient

import "github.com/google/uuid"

type CreateCustomerRequest struct {
	AccountID       uuid.UUID `json:"account_id"`
	Name            string    `json:"name"`
	Email           string    `json:"email"`
	CreditCardToken string    `json:"ccToken"`
}

type CreateCustomerResponse struct {
	StripeID string `json:"stripe+id"`
}
