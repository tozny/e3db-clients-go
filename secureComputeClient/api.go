package secureComputeClient

import (
	"time"

	"github.com/google/uuid"
)

// SubscriptionManagers wraps the Manager object for a subscription
type SubscriptionManagers struct {
	ToznyClientID uuid.UUID `json:"tozny_client_id,omitempty"`
}

// SubscriptionRequest wraps the request to subscribe to a computation
type SubscriptionRequest struct {
	ToznyClientID        uuid.UUID              `json:"tozny_client_id,omitempty"`
	ComputationID        uuid.UUID              `json:"computation_id,omitempty"`
	SubscriptionManagers []SubscriptionManagers `json:"subscription_managers,omitempty"`
}

// SubscriptionResponse wraps the response to subscribing to a  computation
type SubscriptionResponse struct {
	ComputationID       uuid.UUID                      `json:"computation_id,omitempty"`
	RecordTypesRequired []ComputationRecordRequirement `json:"record_types_required,omitempty"`
}

// UpdateSubscriptionRequest wraps the request to update a computation information
type UpdateSubscriptionRequest struct {
	ComputationID        uuid.UUID              `json:"computation_id,omitempty"`
	SubscriptionManagers []SubscriptionManagers `json:"subscription_managers,omitempty"`
}

// UnsubscribeRequest wraps the request to unsubscribe to a computation
type UnsubscribeRequest struct {
	ToznyClientID uuid.UUID
	ComputationID uuid.UUID
}

// FetchSubscriptionsRequest wraps the request to fetch all subscriptions
type FetchSubscriptionsRequest struct {
	ToznyClientID uuid.UUID
}

// ComputationRecordRequirement wraps all required content type
type ComputationRecordRequirement struct {
	ContentType string `json:"content_type,omitempty"`
	SharedWith  string `json:"shared_with,omitempty"`
	Description string `json:"description,omitempty"`
}

// ComputationDataRequirement wraps all required user data
type ComputationDataRequirement struct {
	DataTag     string `json:"data_tag,omitempty"`
	SharedWith  string `json:"shared_with,omitempty"`
	Description string `json:"description,omitempty"`
}

// Computation wraps all data for a computation
type Computation struct {
	ComputationID        uuid.UUID                      `json:"computation_id,omitempty"`
	SubscriptionManagers []SubscriptionManagers         `json:"subscription_managers,omitempty"`
	RecordTypesRequired  []ComputationRecordRequirement `json:"record_types_required,omitempty"`
	DataRequired         []ComputationDataRequirement   `json:"data_required,omitempty"`
}

// ComputationRequest wraps all information for a computation request
type ComputationRequest struct {
	ComputationID      uuid.UUID
	ToznyClientID      uuid.UUID           `json:"tozny_client_id,omitempty"`
	DataStartTimestamp time.Time           `json:"data_start_timestamp,omitempty"`
	DataEndTimestamp   time.Time           `json:"data_end_timestamp,omitempty"`
	DataRequired       []map[string]string `json:"data_required,omitempty"`
}

// ComputationResponse wraps all computations for a client response
type ComputationResponse struct {
	Computations []Computation `json:"computations,omitempty"`
}
