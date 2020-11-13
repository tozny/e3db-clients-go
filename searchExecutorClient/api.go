package searchExecutorClient

import (
	"time"

	"github.com/tozny/e3db-clients-go/pdsClient"
)

// ExecutorQueryRequest represents a valid POST call to /v2/search.
type ExecutorQueryRequest struct {
	NextToken         int           `json:"next_token"`          // Provided when paginating through query results
	Limit             int           `json:"limit"`               // Defaults to 50, maximum of 100 results
	IncludeAllWriters bool          `json:"include_all_writers"` // Defaults to false
	IncludeData       bool          `json:"include_data"`        // Defaults to false
	Match             []QueryParams `json:"match"`
	Exclude           []QueryParams `json:"exclude"`
	Range             QueryRange    `json:"range"`
	Async             bool          `json:"async"`
}

// QueryParams contains the high level construction of the query strategy and values.
type QueryParams struct {
	Condition string     `json:"condition"` // "OR|AND". Whether all term values have to be present on a search record or only at least one. Defaults to OR.
	Strategy  string     `json:"strategy"`  // "EXACT|FUZZY|WILDCARD|REGEXP". What strategy to use when evaluating whether a search record value matches the query term. Defaults to EXACT.
	Terms     QueryTerms `json:"terms"`     // The value to use when checking for a matching search record.
}

// QueryTerms contains the specific values on which to query.
type QueryTerms struct {
	Keys         []string          `json:"keys"`
	Values       []string          `json:"values"`
	Tags         map[string]string `json:"tags"`
	RecordIDs    []string          `json:"record_ids"`
	WriterIDs    []string          `json:"writer_ids"`
	UserIDs      []string          `json:"user_ids"`
	ContentTypes []string          `json:"content_types"`
	SharedWith   []string          `json:"shared_with"`
}

// QueryRange contains the time range in which to query.
type QueryRange struct {
	RangeKey   string    `json:"range_key"`   // CREATED|MODIFIED
	TimeFormat string    `json:"time_format"` // "Unix|ISO8601DateTime"
	TimeZone   string    `json:"time_zone"`   // Converts Before and "After" from the given timezone to UTC normalized time when searching
	Before     time.Time `json:"before"`
	After      time.Time `json:"after"`
}

// ExecutorQueryResponse contains the high level information for the response sent to client by the executor.
type ExecutorQueryResponse struct {
	ResultList   []pdsClient.ListedRecord `json:"results"`
	LastIndex    int                      `json:"last_index"`
	TotalResults int64                    `json:"total_results"`
	SearchID     string                   `json:"search_id"`
}
