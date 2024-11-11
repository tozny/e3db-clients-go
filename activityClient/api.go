package activityClient

type Notification struct {
	NotificationID   string                 `json:"notification_id"`
	EventType        string                 `json:"event_type"`
	ActorClientID    string                 `json:"actor_client_id"`
	ReceiverClientID string                 `json:"receiver_client_id"`
	Data             map[string]interface{} `json:"data"`
	RequestTime      string                 `json:"request_time"`
}

type AddNotificationsRequest struct {
	Notifications []Notification `json:"notifications"`
}

type NotificationsResponse struct {
	Notifications []Notification `json:"notifications"`
	NextToken     int            `json:"next_token"`
}

type NotificationCountResponse struct {
	Count string `json:"count"`
}

type UpdateNotificationsStatus struct {
	Status          string   `json:"status"`
	NotificationIDs []string `json:"notification_ids"`
}
