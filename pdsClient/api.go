package pdsClient

import (
    "time"
)

// ListRecordsRequest represents a valid ListRecord call to the PDS service.
type ListRecordsRequest struct {
    Count       int  `json:"count"`                  //The maximum number of records to return.
    IncludeData bool `json:"include_data,omitempty"` //If true, include record data with results.

    WriterIDs         []string          `json:"writer_ids,omitempty"`    //If not empty, limit results to records written by the given set of IDs.
    UserIDs           []string          `json:"user_ids,omitempty"`      //If not null, limit results to records about given set of IDs.
    RecordIDs         []string          `json:"record_ids,omitempty"`    //If not empty, limit results to the records specified.
    ContentTypes      []string          `json:"content_types,omitempty"` //If not empty, limit results to records of the given types.
    AfterIndex        int               `json:"after_index,omitempty"`   //If greater than 0, limit results to the records appearing "after" the given index.
    Plain             map[string]string `json:"plain,omitempty"`
    IncludeAllWriters bool              `json:"include_all_writers,omitempty"` //If true, include all records shared with this client.
}

// Meta contains meta-information about an E3DB record, such as
// who wrote it, when it was written, and the type of the data stored.
type Meta struct {
    RecordID     string            `json:"record_id,omitempty"`
    WriterID     string            `json:"writer_id"`
    UserID       string            `json:"user_id"`
    Type         string            `json:"type"`
    Plain        map[string]string `json:"plain"`
    Created      time.Time         `json:"created"`
    LastModified time.Time         `json:"last_modified"`
    Version      string            `json:"version,omitempty"`
}

// GetEAKResponse contains the api representation of fetching an encrypted access key.
type GetEAKResponse struct {
    EAK                 string    `json:"eak"`
    AuthorizerID        string    `json:"authorizer_id"`
    AuthorizerPublicKey ClientKey `json:"authorizer_public_key"`
}

// ClientKey contains a cryptographic key for use in client operations.
type ClientKey struct {
    Curve25519 string `json:"curve25519"`
}

// ListedRecord contains the api List
// representation for a record
type ListedRecord struct {
    Meta      Meta              `json:"meta"`
    Data      map[string]string `json:"record_data"`
    AccessKey *GetEAKResponse   `json:"access_key"`
}

// ListRecordResults contains a set of listed records as a result of making a ListRecord call.
type ListRecordsResult struct {
    Results   []ListedRecord `json:"results"`
    LastIndex int            `json:"last_index"`
}
