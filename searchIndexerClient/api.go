package searchIndexerClient

// IndexRecordRequest wraps a request to the Indexer's /index endpoint
type IndexRecordRequest struct {
	RecordId string `json:"record_id"` // The id of the Record to index from the Personal Data Service(PDS).
}

// BatchIndexRecordRequest wraps a request to the Indexer's /index/batch endpoint
type BatchIndexRecordRequest struct {
	RecordIds []string `json:"record_ids"`
}

// IndexRecordResponse represents a response to a request to the Indexer's /index endpoint
type IndexRecordResponse IndexRecordRequest

// BatchIndexRecordResponse represents a response to a request to the Indexer's /index/batch endpoint
type BatchIndexRecordResponse BatchIndexRecordRequest
