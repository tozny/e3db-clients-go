package searchIndexerClient

// IndexRecordRequest wraps a request to the Indexer's /index endpoint
type IndexRecordRequest struct {
    RecordId string `json:"record_id"` // The id of the Record to index from the Personal Data Service(PDS).
}

// IndexRecordRequest represents a response to a request to the Indexer's /index endpoint
type IndexRecordResponse IndexRecordRequest
