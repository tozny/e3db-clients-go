package hookClient

// HookTrigger wraps parameters controlling
// when a hook will be fired, namely which APIEvent triggers
// the hook and whether the trigger is live/enabled.
type HookTrigger struct {
	Enabled  bool   `json:"enabled"`   // Whether this trigger should fire the hook
	APIEvent string `json:"api_event"` // The APIEvent that should trigger this hook
}

// CreateHookRequest wraps the parameters
// required for a valid CreateHook request.
type CreateHookRequest struct {
	WebhookURL string        `json:"webhook_url"`
	Triggers   []HookTrigger `json:"triggers"`
}

// CreateHookResponse represents a response from calling the CreateHook endpoint.
type CreateHookResponse struct {
	WebhookID  int           `json:"webhook_id"`
	WebhookURL string        `json:"webhook_url"`
	Triggers   []HookTrigger `json:"triggers"`
}

// Hook represents the hook service Hook object
// a mapping from event triggers to webhook endpoint to fire for the given trigger
type Hook struct {
	WebhookID  int           `json:"webhook_id"`
	WebhookURL string        `json:"webhook_url"`
	Triggers   []HookTrigger `json:"triggers"`
}

// ListHooksResponse represents a response from calling the ListHooks endpoint, namely a list of hooks for the requesting client's account.
type ListHooksResponse struct {
	Hooks []Hook `json:"hooks"`
}
