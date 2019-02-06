package pdsClient

import (
	"context"
	"fmt"
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
	var createdRecordIds []string
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
		createdRecordIds = append(createdRecordIds, record.Metadata.RecordID)
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
	for _, id := range createdRecordIds {
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
	readerId := "3a0649b8-4e4c-4cd0-b909-1179c4d74d42"
	_, err := e3dbPDS.InternalAllowedReads(ctx, readerId)
	if err != nil {
		t.Error(err)
	}
}
