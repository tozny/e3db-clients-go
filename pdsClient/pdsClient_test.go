package pdsClient

import (
	"context"
	"fmt"
	"github.com/google/uuid"
	"github.com/tozny/e3db-clients-go"
	"github.com/tozny/e3db-go/v2"
	"os"
	"testing"
	"time"
)

var e3dbBaseURL = os.Getenv("E3DB_API_URL")
var e3dbAPIKey = os.Getenv("E3DB_API_KEY_ID")
var e3dbAPISecret = os.Getenv("E3DB_API_KEY_SECRET")

var ValidClientConfig = e3dbClients.ClientConfig{
	APIKey:    e3dbAPIKey,
	APISecret: e3dbAPISecret,
	Host:      e3dbBaseURL,
}

var e3dbPDS = New(ValidClientConfig)

func RegisterClient(email string) (E3dbPDSClient, string, error) {
	var user E3dbPDSClient
	publicKey, privateKey, err := e3db.GenerateKeyPair()
	if err != nil {
		return user, "", err
	}
	params := RegisterClientRequest{
		Email:      email,
		PublicKey:  ClientKey{publicKey},
		PrivateKey: ClientKey{privateKey},
	}
	ctx := context.TODO()
	resp, err := e3dbPDS.InternalRegisterClient(ctx, params)
	if err != nil {
		return user, "", err
	}
	user = New(e3dbClients.ClientConfig{
		APIKey:    resp.APIKeyID,
		APISecret: resp.APISecret,
		Host:      e3dbBaseURL,
	})
	return user, resp.ClientID, err
}

var validPDSUser, validPDSUserID, _ = RegisterClient(fmt.Sprintf("test+pdsClient+%d@tozny.com", time.Now().Unix()))

var defaultPDSUserRecordType = "integration_tests"

func MakeClientWriterForRecordType(pdsUser E3dbPDSClient, clientID string, recordType string) (string, error) {
	ctx := context.TODO()
	putEAKParams := PutAccessKeyRequest{
		WriterID:           clientID,
		UserID:             clientID,
		ReaderID:           clientID,
		RecordType:         recordType,
		EncryptedAccessKey: "SOMERANDOMNPOTENTIALLYNONVALIDKEY",
	}
	resp, err := pdsUser.PutAccessKey(ctx, putEAKParams)
	return resp.EncryptedAccessKey, err
}

var validPDSEncryptedAccessKey, _ = MakeClientWriterForRecordType(validPDSUser, validPDSUserID, defaultPDSUserRecordType)

func TestListRecordsSucceedsWithValidClientCredentials(t *testing.T) {
	var createdRecordIDs []string
	ctx := context.TODO()
	// Create two records with that client
	for i := 0; i < 2; i++ {
		data := map[string]string{"data": "unencrypted"}
		recordToWrite := WriteRecordRequest{
			Data: data,
			Metadata: Meta{
				Type:     defaultPDSUserRecordType,
				WriterID: validPDSUserID,
				UserID:   validPDSUserID,
				Plain:    map[string]string{"key": "value"},
			},
		}
		record, err := validPDSUser.WriteRecord(ctx, recordToWrite)
		if err != nil {
			t.Error(err)
		}
		createdRecordIDs = append(createdRecordIDs, record.Metadata.RecordID)
	}
	// List records and verify the created records are present
	params := ListRecordsRequest{
		Count:             50,
		IncludeAllWriters: true,
	}
	tok, err := validPDSUser.GetToken(ctx)
	proxyListedRecords, err := e3dbPDS.ProxyListRecords(ctx, tok.AccessToken, params) // proxy record
	listedRecords, err := validPDSUser.ListRecords(ctx, params)                       // user request record
	if err != nil {
		t.Error(err)
	}
	for _, id := range createdRecordIDs {
		var match bool
		for _, listedRecord := range listedRecords.Results {
			if id == listedRecord.Metadata.RecordID {
				match = true
				break
			}
		}
		for _, listedRecord := range proxyListedRecords.Results {
			if id == listedRecord.Metadata.RecordID {
				match = true
				break
			}
		}
		if !match {
			t.Errorf("Failed to find created record with id %s in response %v\n", id, listedRecords)
		}
	}
}

func TestInternalGetRecordSucceedsWithValidClientCredentials(t *testing.T) {
	ctx := context.TODO()
	// Create record with e3db external client
	data := map[string]string{"data": "unencrypted"}
	recordToWrite := WriteRecordRequest{
		Data: data,
		Metadata: Meta{
			Type:     defaultPDSUserRecordType,
			WriterID: validPDSUserID,
			UserID:   validPDSUserID,
			Plain:    map[string]string{"key": "value"},
		},
	}
	createdRecord, err := validPDSUser.WriteRecord(ctx, recordToWrite)
	if err != nil {
		t.Error(err)
	}
	// Fetch that record with e3db internal client
	e3dbPDS := New(ValidClientConfig)

	resp, err := e3dbPDS.InternalGetRecord(ctx, createdRecord.Metadata.RecordID)
	if err != nil {
		t.Error(err)
	}
	for createdKey, createdValue := range recordToWrite.Metadata.Plain {
		var match bool
		for retrievedKey, retrievedValue := range resp.Metadata.Plain {
			if retrievedKey == createdKey && retrievedValue == createdValue {
				match = true
				break
			}
			if !match {
				t.Logf("Returned record did not match previously created record, missing plain object %s=>%s", createdKey, createdValue)
			}
		}
	}
}

func TestInternalAllowedReadReturnsValidResponse(t *testing.T) {
	ctx := context.TODO()
	readerID := "3a0649b8-4e4c-4cd0-b909-1179c4d74d42"
	_, err := e3dbPDS.InternalAllowedReads(ctx, readerID)
	if err != nil {
		t.Error(err)
	}
}

func TestGetAccessKeyReturnsPuttedAccessKey(t *testing.T) {
	// Put an access key
	recordType := uuid.New().String()
	ctx := context.TODO()
	putEAKParams := PutAccessKeyRequest{
		WriterID:           validPDSUserID,
		UserID:             validPDSUserID,
		ReaderID:           validPDSUserID,
		RecordType:         recordType,
		EncryptedAccessKey: "SOMERANDOMNPOTENTIALLYNONVALIDKEY",
	}
	_, err := validPDSUser.PutAccessKey(ctx, putEAKParams)
	if err != nil {
		t.Errorf("Error trying to put access key for %+v %s", validPDSUser, err)
	}
	getEAKParams := GetAccessKeyRequest{
		WriterID:   validPDSUserID,
		UserID:     validPDSUserID,
		ReaderID:   validPDSUserID,
		RecordType: recordType,
	}
	getResponse, err := validPDSUser.GetAccessKey(ctx, getEAKParams)
	if err != nil {
		t.Errorf("Error trying to put access key for %+v %s", validPDSUser, err)
	}
	if getResponse.AuthorizerID != validPDSUserID {
		t.Errorf("Expected ket to have been authorized by %s, but got %+v", validPDSUserID, getResponse)
	}
}

func TestSharedRecordsCanBeFetchedBySharee(t *testing.T) {
	// Create a client to share records with
	sharee, shareeID, err := RegisterClient(fmt.Sprintf("test+pdsClient+%d@tozny.com", uuid.New()))
	if err != nil {
		t.Errorf("Error creating client to share records with: %s", err)
	}
	// Create records to share with this client
	ctx := context.TODO()
	data := map[string]string{"data": "unencrypted"}
	recordToWrite := WriteRecordRequest{
		Data: data,
		Metadata: Meta{
			Type:     defaultPDSUserRecordType,
			WriterID: validPDSUserID,
			UserID:   validPDSUserID,
			Plain:    map[string]string{"key": "value"},
		},
	}
	createdRecord, err := validPDSUser.WriteRecord(ctx, recordToWrite)
	if err != nil {
		t.Errorf("Error writing record to share %s\n", err)
	}
	// Share records of type created with sharee client
	err = validPDSUser.ShareRecords(ctx, ShareRecordsRequest{
		UserID:     validPDSUserID,
		WriterID:   validPDSUserID,
		ReaderID:   shareeID,
		RecordType: defaultPDSUserRecordType,
	})
	if err != nil {
		t.Errorf("Error %s sharing records of type %swith client %+v\n", err, defaultPDSUserRecordType, sharee)
	}
	// Verify sharee can fetch records of type shared
	listResponse, err := sharee.ListRecords(ctx, ListRecordsRequest{
		ContentTypes:      []string{defaultPDSUserRecordType},
		IncludeAllWriters: true,
	})
	if err != nil {
		t.Errorf("Error %s listing records for client %+v\n", err, sharee)
	}
	var found bool
	for _, record := range listResponse.Results {
		if record.Metadata.RecordID == createdRecord.Metadata.RecordID {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Failed to find shared records in list records results %+v\n", listResponse)
	}
}

func TestDeleteRecord(t *testing.T) {
	// Create record to delete
	ctx := context.TODO()
	data := map[string]string{"data": "unencrypted"}
	recordToWrite := WriteRecordRequest{
		Data: data,
		Metadata: Meta{
			Type:     defaultPDSUserRecordType,
			WriterID: validPDSUserID,
			UserID:   validPDSUserID,
			Plain:    map[string]string{"key": "value"},
		},
	}
	createdRecord, err := validPDSUser.WriteRecord(ctx, recordToWrite)
	if err != nil {
		t.Errorf("Error writing record to delete %s\n", err)
	}
	deleteRequest := DeleteRecordRequest{
		RecordID: createdRecord.Metadata.RecordID,
	}
	err = validPDSUser.DeleteRecord(ctx, deleteRequest)
	if err != nil {
		t.Errorf("Error deleting written record %s\n", err)
	}
}
func TestFindModifiedRecords(t *testing.T) {
	// Create record to delete
	startTime := time.Now()
	ctx := context.TODO()
	data := map[string]string{"data": "unencrypted"}
	recordToWrite := WriteRecordRequest{
		Data: data,
		Metadata: Meta{
			Type:     defaultPDSUserRecordType,
			WriterID: validPDSUserID,
			UserID:   validPDSUserID,
			Plain:    map[string]string{"key": "value"},
		},
	}
	createdRecord, err := validPDSUser.WriteRecord(ctx, recordToWrite)
	if err != nil {
		t.Errorf("Error writing record to get modified %s\n", err)
	}
	endTime := time.Now()

	modifiedRecordRequest := InternalModifiedSearchRequest{
		NextToken: 0,
		Range: InternalModifiedRange{
			After:  startTime,
			Before: endTime,
		},
	}
	modifiedResponse, err := validPDSUser.InternalModifiedSearch(ctx, modifiedRecordRequest)
	if err != nil {
		t.Errorf("Error getting modified records %s\n", err)
	}
	found := false
	for _, record := range modifiedResponse.Records {
		if record.Metadata.RecordID == createdRecord.Metadata.RecordID {
			found = true
		}
	}
	if found != true {
		t.Error("Could not find modified we wrote record")
	}

}
