package pdsClient

import (
	"time"
)

const BatchReadRecordLimit = 1000

// AddAuthorizedWriterRequest wraps the needed parameters
// to authorize a client to share records of a specified type on behalf of another client
type AddAuthorizedWriterRequest struct {
	UserID       string
	WriterID     string
	AuthorizerID string
	RecordType   string
}

// ShareRecordsRequest wraps the needed parameters
// to share records of a specified type from one
// user to another
type AuthorizerShareRecordsRequest struct {
	UserID       string
	WriterID     string
	AuthorizerID string
	ReaderID     string
	RecordType   string
}

type AuthorizerUnshareRecordsRequest = AuthorizerShareRecordsRequest

// ShareRecordsRequest wraps the needed parameters
// to share records of a specified type from one
// user to another
type ShareRecordsRequest struct {
	UserID     string
	WriterID   string
	ReaderID   string
	RecordType string
}

// InternalAllowedReadsRequest represents a valid request to the AllowedReads endpoint
type InternalAllowedReadsRequest struct {
	ReaderID string
}

// InternalAllowedReadsResponse represents a response from calling the AllowedReads endpoint
type InternalAllowedReadsResponse struct {
	AllowedReads []AllowedRead `json:"allowed_reads"`
}

// InternalAllowedReadersForPolicyRequest a valid request to internal endpoint for allowed readers of a record type and writer id (access policy).
type InternalAllowedReadersForPolicyRequest struct {
	WriterID    string `json:"writer_id"`
	ContentType string `json:"content_type"`
}

// InternalAllowedReadersForPolicyResponse represents a response to allowed readers for policy endpoint, returning allowed clientIDs that can read the specified records.
type InternalAllowedReadersForPolicyResponse struct {
	ReaderIDs []string `json:"reader_ids"`
}

// AllowedRead represents an access policy that allows an e3db user to read records of a specified type written and owned by specified users.
type AllowedRead struct {
	UserID      string `json:"user_id"`
	WriterID    string `json:"writer_id"`
	ContentType string `json:"content_type"`
}

// InternalSearchRequest represents a valid request to the internal records search endpoint
type InternalSearchRequest struct {
	NextToken    int                    `json:"next_token,omitempty"`
	Range        *InternalModifiedRange `json:"range,omitempty"`
	WriterIDs    []string               `json:"writer_ids,omitempty"`    //If not empty, limit results to records written by the given set of IDs.
	UserIDs      []string               `json:"user_ids,omitempty"`      //If not null, limit results to records about given set of IDs.
	ContentTypes []string               `json:"content_types,omitempty"` //If not empty, limit results to records of the given types.
}

// InternalSearchResponse represents a response from calling the internal records search endpoint
type InternalSearchResponse struct {
	NextToken int      `json:"next_token"`
	Records   []Record `json:"records"`
}

// InternalSearchAllowedReadsRequest represents a valid request to internal allowed reads search
// for getting a list of allowed reads that match the request parameters.
type InternalSearchAllowedReadsRequest = InternalSearchRequest

// InternalSearchAllowedReadsResponse represents a response from calling the internal allowed reads search endpoint
type InternalSearchAllowedReadsResponse struct {
	NextToken    int           `json:"next_token"`
	AllowedReads []AllowedRead `json:"allowed_reads"`
}

// InternalModifiedRange represents the range parameter for the internal modified search request
type InternalModifiedRange struct {
	After  time.Time `json:"modified_after"`
	Before time.Time `json:"modified_before"`
}

// RegisterClientRequest represents a request to register a client.
type RegisterClientRequest struct {
	Email      string    `json:"email"`
	PublicKey  ClientKey `json:"public_key"`
	PrivateKey ClientKey `json:"private_key"`
}

// RegisterClientResponse represents a response from an attempt to register a client.
type RegisterClientResponse struct {
	ClientID  string `json:"client_id"`
	APIKeyID  string `json:"api_key_id"`
	APISecret string `json:"api_secret"`
}

// Record wraps details about an E3db API record object.
type Record struct {
	Metadata Meta              `json:"meta"`
	Data     map[string]string `json:"data"`
}

// PutAccessKeyRequest represents a request to put an access key into e3db.
type PutAccessKeyRequest struct {
	WriterID           string
	UserID             string
	ReaderID           string
	RecordType         string
	EncryptedAccessKey string `json:"eak"`
}

// CreateAccessKeyForRequest represents a request to create an access key for another client.
type CreateSharingAccessKeyRequest struct {
	WriterID   string
	UserID     string
	ReaderID   string
	RecordType string
}

// CreateAccessKeyForRequest represents a request to create an access key for another client
// for a record type the creator is authorized to share.
type CreateAuthorizerSharingAccessKeyRequest struct {
	WriterID     string
	UserID       string
	ReaderID     string
	AuthorizerID string
	RecordType   string
}

// PutAccessKeyResponse represents a response from trying to put an access key into e3db.
type PutAccessKeyResponse struct {
	SignerID            string `json:"signer_id"`
	SignerSigningKey    string `json:"signer_signing_key"`
	AuthorizerPublicKey string `json:"authorizer_public_key"`
	EncryptedAccessKey  string `json:"eak"`
}

// WriteRecordRequest represents a request to write a record via the e3db api.
type WriteRecordRequest = Record

// WriteRecordResponse represents a response from trying to write a record via the e3db api.
type WriteRecordResponse = Record

// DeleteRecordRequest represents a request to delete a record via e3db api.
type DeleteRecordRequest struct {
	RecordID string `json:"record_id"`
}

// ListRecordsRequest represents a valid ListRecord call to the PDS service.
type ListRecordsRequest struct {
	Count       int  `json:"count,omitempty"`        //The maximum number of records to return.
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
	// Certain pds endpoints such as WriteRecord return 400 Bad Request if this key is present in the JSON
	// https://www.sohamkamani.com/blog/golang/2018-07-19-golang-omitempty/
	FileMeta *FileMeta `json:"file_meta,omitempty"`
}

// FileMeta contains meta-information about files associated with E3DB Large File Records,
// such as file name, S3 url, and other file data.
type FileMeta struct {
	FileURL     string `json:"file_url,omitempty"`
	FileName    string `json:"file_name,omitempty"`
	Size        int    `json:"size,omitempty"`
	Compression string `json:"compression,omitempty"`
	Checksum    string `json:"checksum,omitempty"`
}

// GetEAKResponse contains the api representation of fetching an encrypted access key.
type GetEAKResponse struct {
	EAK                 string    `json:"eak"`
	AuthorizerID        string    `json:"authorizer_id"`
	AuthorizerPublicKey ClientKey `json:"authorizer_public_key"`
}

// GetAccessKeyResponse contains the api representation of fetching an encrypted access key.
type GetAccessKeyResponse = GetEAKResponse

// GetAccessKeyRequest represents a request to get an access key from e3db.
type GetAccessKeyRequest struct {
	WriterID   string
	UserID     string
	ReaderID   string
	RecordType string
}

type DeleteAccessKeyRequest = GetAccessKeyRequest

// ClientKey contains a cryptographic key for use in client operations.
type ClientKey struct {
	Curve25519 string `json:"curve25519"`
}

// ListedRecord contains the api List
// representation for a record
type ListedRecord struct {
	Metadata  Meta              `json:"meta"`
	Data      map[string]string `json:"record_data"`
	AccessKey *GetEAKResponse   `json:"access_key"`
}

// InternalGetRecordResponse wraps the api response from a
// GET internal/v1/records call
type InternalGetRecordResponse struct {
	Metadata Meta `json:"meta"`
}

// ListRecordResults contains a set of listed records as a result of making a ListRecord call.
type ListRecordsResult struct {
	Results   []ListedRecord `json:"results"`
	LastIndex int            `json:"last_index"`
}

type BatchGetRecordsRequest struct {
	RecordIDs   []string `json:"record_ids"`
	IncludeData bool     `json:"include_data"`
}

type BatchGetRecordsResult struct {
	Records []ListedRecord `json:"records"`
}

type GetOrCreateAccessKeyRequest struct {
	WriterID   string // the tozny client that wrote the access key
	UserID     string // the tozny client that the access key belongs to
	ReaderID   string // the tozny client that this access key is written for
	RecordType string // the type of records this access key is valid for
}

type CreateSharedAccessKeyRequest struct {
	WriterID           string
	UserID             string
	ReaderID           string
	RecordType         string
	EncryptedAccessKey string
	ShareePublicKey    string
}

type BulkDeleteResponse struct {
	DeleteCount int `json:"delete_count"`
}
