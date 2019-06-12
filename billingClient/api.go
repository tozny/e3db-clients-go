package billingclient

import (
	"time"

	"github.com/google/uuid"
)

type CreateCustomerRequest struct {
	AccountID       uuid.UUID `json:"account_id"`
	Name            string    `json:"name"`
	Email           string    `json:"email"`
	CreditCardToken string    `json:"ccToken"`
}

type CreateCustomerResponse struct {
	StripeID string `json:"stripe_id"`
}

// InternalGetMeteredSubscriptionInfoResponse represents a response from calling the billing service
// internal/v1/billing/subscription-info/{account-id} endpoint
type InternalGetMeteredSubscriptionInfoResponse struct {
	StripeID                       string    `json:"stripe_id"`
	SubscriptionID                 string    `json:"stripe_subscription_id"`
	SubscriptionItemID             string    `json:"stripe_subscription_item_id"`
	SubscriptionCreatedAt          time.Time `json:"subscription_created_at"`
	SubscriptionCurrentPeriodStart time.Time `json:"subscription_current_period_start"`
	SubscriptionCurrentPeriodEnd   time.Time `json:"subscription_current_period_end"`
}

type GetAccountStatusResponse struct {
	AccountActive   bool      `json:"account_active"`
	IsTrial         bool      `json:"is_trial"`
	TrialPeriodEnds time.Time `json:"trial_period_ends"`
	IsLegacy        bool      `json:"is_legacy"`
	IsGoodStanding  bool      `json:"is_good_standing"`
}
