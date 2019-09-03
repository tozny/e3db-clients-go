package pdsClient_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tozny/e3db-clients-go"
	"github.com/tozny/e3db-clients-go/accountClient"
	"github.com/tozny/e3db-clients-go/pdsClient"
	"github.com/tozny/e3db-clients-go/test"
)

var (
	toznyCyclopsHost         = os.Getenv("TOZNY_CYCLOPS_SERVICE_HOST")
	e3dbPDSHost              = os.Getenv("E3DB_STORAGE_SERVICE_HOST")
	e3dbAuthHost             = os.Getenv("E3DB_AUTH_SERVICE_HOST")
	e3dbAccountHost          = os.Getenv("E3DB_ACCOUNT_SERVICE_HOST")
	e3dbClientHost           = os.Getenv("E3DB_CLIENT_SERVICE_HOST")
	e3dbAPIKey               = os.Getenv("E3DB_API_KEY_ID")
	e3dbAPISecret            = os.Getenv("E3DB_API_KEY_SECRET")
	ValidBootPDSClientConfig = e3dbClients.ClientConfig{
		APIKey:    e3dbAPIKey,
		APISecret: e3dbAPISecret,
		Host:      toznyCyclopsHost,
		AuthNHost: e3dbAuthHost,
	}
	bootPDSClient                    = pdsClient.New(ValidBootPDSClientConfig)
	ValidInternalBootPDSClientConfig = e3dbClients.ClientConfig{
		APIKey:    e3dbAPIKey,
		APISecret: e3dbAPISecret,
		Host:      e3dbPDSHost,
		AuthNHost: e3dbAuthHost,
	}
	bootInternalPDSClient        = pdsClient.New(ValidInternalBootPDSClientConfig)
	ValidBootAccountClientConfig = e3dbClients.ClientConfig{
		APIKey:    e3dbAPIKey,
		APISecret: e3dbAPISecret,
		Host:      e3dbAccountHost,
		AuthNHost: e3dbAuthHost,
	}
	bootAccountClient         = accountClient.New(ValidBootAccountClientConfig)
	validPDSUser              pdsClient.E3dbPDSClient
	validPDSUserID            string
	validPDSRegistrationToken string
	defaultPDSUserRecordType  = "integration_tests"
	testContext               = context.Background()
)

//TestMain gives all tests access to a client "validPDSUser" who is authorized to write to a default record type.
func TestMain(m *testing.M) {
	err := setup()
	if err != nil {
		fmt.Printf("Could not perform setup for tests due to %s", err)
		os.Exit(1)
	}
	code := m.Run()
	os.Exit(code)
}

func setup() error {
	accountTag := uuid.New().String()
	queenAccountConfig, createAccountResp, err := test.MakeE3DBAccount(&testing.T{}, &bootAccountClient, accountTag, e3dbAuthHost)
	if err != nil {
		return err
	}
	queenAccountClient := accountClient.New(queenAccountConfig)
	accountServiceJWT := createAccountResp.AccountServiceToken

	queenAccountConfig.Host = toznyCyclopsHost
	validPDSUser = pdsClient.New(queenAccountConfig)
	validPDSUserID = createAccountResp.Account.Client.ClientID
	_, err = test.MakeClientWriterForRecordType(validPDSUser, validPDSUserID, defaultPDSUserRecordType)
	if err != nil {
		return err
	}
	validPDSRegistrationToken, err = test.CreateRegistrationToken(&queenAccountClient, accountServiceJWT)
	return err
}

func TestEncryptRecordReturnsRecordWithEncryptedData(t *testing.T) {
	dataKeyToEncrypt := "data"
	data := map[string]string{dataKeyToEncrypt: "unencrypted"}
	recordToWrite := pdsClient.WriteRecordRequest{
		Data: data,
		Metadata: pdsClient.Meta{
			Type:     defaultPDSUserRecordType,
			WriterID: validPDSUserID,
			UserID:   validPDSUserID,
			Plain:    map[string]string{"key": "value"},
		},
	}
	encryptedRecord, err := validPDSUser.EncryptRecord(testContext, recordToWrite)
	if err != nil {
		t.Fatalf("error %s encrypting record %+v", err, recordToWrite)
	}
	if encryptedRecord.Data[dataKeyToEncrypt] == data[dataKeyToEncrypt] {
		t.Errorf("Expected encrypted record %+v data field %s to not equal the unencrypted record's %v data field", encryptedRecord, dataKeyToEncrypt, recordToWrite)
	}
}

func TestEncryptDecryptRecordReturnsRecordWithCorrectDecryptedData(t *testing.T) {
	dataKeyToEncrypt := "data"
	data := map[string]string{dataKeyToEncrypt: "unencrypted"}
	recordToWrite := pdsClient.WriteRecordRequest{
		Data: data,
		Metadata: pdsClient.Meta{
			Type:     defaultPDSUserRecordType,
			WriterID: validPDSUserID,
			UserID:   validPDSUserID,
			Plain:    map[string]string{"key": "value"},
		},
	}
	encryptedRecord, err := validPDSUser.EncryptRecord(testContext, recordToWrite)
	if err != nil {
		t.Fatalf("error %s encrypting record %+v", err, recordToWrite)
	}
	decryptedRecord, err := validPDSUser.DecryptRecord(testContext, encryptedRecord)
	if err != nil {
		t.Fatalf("error %s decrypting record %+v", err, encryptedRecord)
	}
	if decryptedRecord.Data[dataKeyToEncrypt] != recordToWrite.Data[dataKeyToEncrypt] {
		t.Errorf("expected the encrypted and decrypted record %+v data field %s to equal the plain text value for %+v", decryptedRecord, dataKeyToEncrypt, recordToWrite)
	}
}

func TestBatchGetRecordsReturnsBatchofUserRecords(t *testing.T) {
	var createdRecordIDs []string
	ctx := context.TODO()
	// Create two records with the default client
	for i := 0; i < 2; i++ {
		data := map[string]string{"data": "unencrypted"}
		recordToWrite := pdsClient.WriteRecordRequest{
			Data: data,
			Metadata: pdsClient.Meta{
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
	// Batch get records and verify the created records are returned
	params := pdsClient.BatchGetRecordsRequest{
		RecordIDs: createdRecordIDs,
	}
	batchRecords, err := validPDSUser.BatchGetRecords(ctx, params)
	if err != nil {
		t.Errorf("err %s making BatchGetRecords call %+v\n", err, params)
	}
	for _, id := range createdRecordIDs {
		var match bool
		for _, batchRecord := range batchRecords.Records {
			if id == batchRecord.Metadata.RecordID {
				match = true
				break
			}
		}
		if !match {
			t.Errorf("Failed to find created record with id %s in response %v\n", id, batchRecords)
		}
	}
}

func TestBatchGetRecordsDoesNotReturnsDeletedRecords(t *testing.T) {
	var createdRecordIDs []string
	ctx := context.TODO()
	// Create two records with the default client
	for i := 0; i < 2; i++ {
		data := map[string]string{"data": "unencrypted"}
		recordToWrite := pdsClient.WriteRecordRequest{
			Data: data,
			Metadata: pdsClient.Meta{
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
	// Batch get records and verify the created records are returned
	params := pdsClient.BatchGetRecordsRequest{
		RecordIDs: createdRecordIDs,
	}
	batchRecords, err := validPDSUser.BatchGetRecords(ctx, params)
	if err != nil {
		t.Errorf("err %s making BatchGetRecords call %+v\n", err, params)
	}
	for _, id := range createdRecordIDs {
		var match bool
		for _, batchRecord := range batchRecords.Records {
			if id == batchRecord.Metadata.RecordID {
				match = true
				break
			}
		}
		if !match {
			t.Errorf("Failed to find created record with id %s in response %v\n", id, batchRecords)
		}
	}
	// Delete the first record
	recordIDToDelete := createdRecordIDs[0]
	deleteParams := pdsClient.DeleteRecordRequest{RecordID: recordIDToDelete}
	err = validPDSUser.DeleteRecord(ctx, deleteParams)
	if err != nil {
		t.Errorf("err %s making DeleteRecord call %+v\n", err, deleteParams)
	}
	// Verify it isn't batch get able anymore
	batchRecords, err = validPDSUser.BatchGetRecords(ctx, params)
	if err != nil {
		t.Errorf("err %s making BatchGetRecords call %+v\n", err, params)
	}
	var listed bool
	for _, batchRecord := range batchRecords.Records {
		if recordIDToDelete == batchRecord.Metadata.RecordID {
			listed = true
			break
		}
	}
	if listed {
		t.Errorf("Expected deleted record %s in to not be returned in batch get response %v\n", recordIDToDelete, batchRecords)
	}
}

func TestBatchGetRecordsReturnsErrorIfTooManyRecordsRequested(t *testing.T) {
	batchRecordRequestCount := pdsClient.BatchReadRecordLimit + 1
	recordIDs := make([]string, batchRecordRequestCount)
	for index := range recordIDs {
		recordIDs[index] = uuid.New().String()
	}
	ctx := context.TODO()

	// Batch get records and verify the created records are returned
	params := pdsClient.BatchGetRecordsRequest{
		RecordIDs: recordIDs,
	}
	_, err := validPDSUser.BatchGetRecords(ctx, params)
	if err == nil {
		t.Errorf("expected err making BatchGetRecords call for records %d\n", batchRecordRequestCount)
	}
}

func TestBatchGetRecordsReturnsSharedRecords(t *testing.T) {
	// Create a client to share records with
	sharee, shareeID, _, err := test.CreatePDSClient(testContext, toznyCyclopsHost, e3dbClientHost, validPDSRegistrationToken, fmt.Sprintf("test+pdsClient+%d@tozny.com", uuid.New()), defaultPDSUserRecordType)
	if err != nil {
		t.Errorf("Error creating client to share records with: %s", err)
	}
	// Create records to share with this client
	ctx := context.TODO()
	data := map[string]string{"data": "unencrypted"}
	recordToWrite := pdsClient.WriteRecordRequest{
		Data: data,
		Metadata: pdsClient.Meta{
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
	err = validPDSUser.ShareRecords(ctx, pdsClient.ShareRecordsRequest{
		UserID:     validPDSUserID,
		WriterID:   validPDSUserID,
		ReaderID:   shareeID,
		RecordType: defaultPDSUserRecordType,
	})
	if err != nil {
		t.Errorf("Error %s sharing records of type %s with client %+v\n", err, defaultPDSUserRecordType, sharee)
	}
	// Verify sharee can fetch records of type shared
	params := pdsClient.BatchGetRecordsRequest{
		RecordIDs: []string{createdRecord.Metadata.RecordID},
	}
	batchRecords, err := sharee.BatchGetRecords(ctx, params)
	if err != nil {
		t.Errorf("err %s making BatchGetRecords call %+v\n", err, params)
	}
	var found bool
	for _, record := range batchRecords.Records {
		if record.Metadata.RecordID == createdRecord.Metadata.RecordID {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Failed to find shared records in batch get records results %+v\n", batchRecords)
	}
}

func TestBatchGetRecordsDoesNotReturnUnsharedRecords(t *testing.T) {
	// Create a client to share records with
	sharee, _, _, err := test.CreatePDSClient(testContext, toznyCyclopsHost, e3dbClientHost, validPDSRegistrationToken, fmt.Sprintf("test+pdsClient+%d@tozny.com", uuid.New()), defaultPDSUserRecordType)
	if err != nil {
		t.Errorf("Error creating client to share records with: %s", err)
	}
	// Create records to share with this client
	ctx := context.TODO()
	data := map[string]string{"data": "unencrypted"}
	recordToWrite := pdsClient.WriteRecordRequest{
		Data: data,
		Metadata: pdsClient.Meta{
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
	// Verify sharee can not fetch unshared record
	params := pdsClient.BatchGetRecordsRequest{
		RecordIDs: []string{createdRecord.Metadata.RecordID},
	}
	batchRecords, err := sharee.BatchGetRecords(ctx, params)
	if err != nil {
		t.Errorf("err %s making BatchGetRecords call %+v\n", err, params)
	}
	var found bool
	for _, record := range batchRecords.Records {
		if record.Metadata.RecordID == createdRecord.Metadata.RecordID {
			found = true
			break
		}
	}
	if found {
		t.Errorf("Found unshared record in batch get records results %+v\n", batchRecords)
	}
}

func TestProxyBatchGetRecordsReturnsBatchofUserRecords(t *testing.T) {
	var createdRecordIDs []string
	ctx := context.TODO()
	// Create two records with the default client
	for i := 0; i < 2; i++ {
		data := map[string]string{"data": "unencrypted"}
		recordToWrite := pdsClient.WriteRecordRequest{
			Data: data,
			Metadata: pdsClient.Meta{
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
	// Batch get records and verify the created records are returned
	params := pdsClient.BatchGetRecordsRequest{
		RecordIDs: createdRecordIDs,
	}
	usersToken, err := validPDSUser.GetToken(ctx)
	if err != nil {
		t.Errorf("err %s making GetToken call for user %+v\n", err, validPDSUser)
	}
	proxyBatchRecords, err := bootPDSClient.ProxyBatchGetRecords(ctx, usersToken.AccessToken, params)
	if err != nil {
		t.Errorf("err %s making ProxyBatchGetRecords call %+v\n on with user token %+v\n", err, usersToken, params)
	}
	for _, id := range createdRecordIDs {
		var match bool
		for _, batchRecord := range proxyBatchRecords.Records {
			if id == batchRecord.Metadata.RecordID {
				match = true
				break
			}
		}
		if !match {
			t.Errorf("Failed to find created record with id %s in response %v\n", id, proxyBatchRecords)
		}
	}
}

func TestListRecordsSucceedsWithValidClientCredentials(t *testing.T) {
	var createdRecordIDs []string
	ctx := context.TODO()
	// Create two records with that client
	for i := 0; i < 2; i++ {
		data := map[string]string{"data": "unencrypted"}
		recordToWrite := pdsClient.WriteRecordRequest{
			Data: data,
			Metadata: pdsClient.Meta{
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
	params := pdsClient.ListRecordsRequest{
		Count:             50,
		IncludeAllWriters: true,
	}
	tok, err := validPDSUser.GetToken(ctx)
	proxyListedRecords, err := bootPDSClient.ProxyListRecords(ctx, tok.AccessToken, params) // proxy record
	listedRecords, err := validPDSUser.ListRecords(ctx, params)                             // user request record
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
	recordToWrite := pdsClient.WriteRecordRequest{
		Data: data,
		Metadata: pdsClient.Meta{
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
	bootPDSClient := pdsClient.New(ValidInternalBootPDSClientConfig)

	resp, err := bootPDSClient.InternalGetRecord(ctx, createdRecord.Metadata.RecordID)
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
	_, err := bootInternalPDSClient.InternalAllowedReads(ctx, readerID)
	if err != nil {
		t.Error(err)
	}
}

func TestGetAccessKeyReturnsPuttedAccessKey(t *testing.T) {
	// Put an access key
	recordType := uuid.New().String()
	ctx := context.TODO()
	putEAKParams := pdsClient.PutAccessKeyRequest{
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
	getEAKParams := pdsClient.GetAccessKeyRequest{
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
	sharee, shareeID, _, err := test.CreatePDSClient(testContext, toznyCyclopsHost, e3dbClientHost, validPDSRegistrationToken, fmt.Sprintf("test+pdsClient+%d@tozny.com", uuid.New()), defaultPDSUserRecordType)
	if err != nil {
		t.Errorf("Error creating client to share records with: %s", err)
	}
	// Create records to share with this client
	ctx := context.TODO()
	data := map[string]string{"data": "unencrypted"}
	recordToWrite := pdsClient.WriteRecordRequest{
		Data: data,
		Metadata: pdsClient.Meta{
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
	err = validPDSUser.ShareRecords(ctx, pdsClient.ShareRecordsRequest{
		UserID:     validPDSUserID,
		WriterID:   validPDSUserID,
		ReaderID:   shareeID,
		RecordType: defaultPDSUserRecordType,
	})
	if err != nil {
		t.Errorf("Error %s sharing records of type %s with client %+v\n", err, defaultPDSUserRecordType, sharee)
	}
	// Verify sharee can fetch records of type shared
	listResponse, err := sharee.ListRecords(ctx, pdsClient.ListRecordsRequest{
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

func TestSharedEncryptedRecordsCanBeDecryptedBySharee(t *testing.T) {
	// Create a client to share records with
	sharee, shareeID, _, err := test.CreatePDSClient(testContext, toznyCyclopsHost, e3dbClientHost, validPDSRegistrationToken, fmt.Sprintf("test+pdsClient+%d@tozny.com", uuid.New()), defaultPDSUserRecordType)
	if err != nil {
		t.Errorf("Error creating client to share records with: %s", err)
	}
	// Create records to share with this client
	ctx := context.TODO()
	dataKeyToEncrypt := "data"
	data := map[string]string{dataKeyToEncrypt: "unencrypted"}
	recordToWrite := pdsClient.WriteRecordRequest{
		Data: data,
		Metadata: pdsClient.Meta{
			Type:     defaultPDSUserRecordType,
			WriterID: validPDSUserID,
			UserID:   validPDSUserID,
			Plain:    map[string]string{"key": "value"},
		},
	}
	encryptedRecord, err := validPDSUser.EncryptRecord(ctx, recordToWrite)
	if err != nil {
		t.Fatalf("error %s encrypting record %+v", err, recordToWrite)
	}
	createdRecord, err := validPDSUser.WriteRecord(ctx, encryptedRecord)
	if err != nil {
		t.Errorf("Error writing record to share %s\n", err)
	}
	// Share records of type created with sharee client
	err = validPDSUser.ShareRecords(ctx, pdsClient.ShareRecordsRequest{
		UserID:     validPDSUserID,
		WriterID:   validPDSUserID,
		ReaderID:   shareeID,
		RecordType: defaultPDSUserRecordType,
	})
	if err != nil {
		t.Errorf("Error %s sharing records of type %s with client %+v\n", err, defaultPDSUserRecordType, sharee)
	}
	// Verify sharee can fetch records of type shared
	listResponse, err := sharee.ListRecords(ctx, pdsClient.ListRecordsRequest{
		ContentTypes:      []string{defaultPDSUserRecordType},
		IncludeAllWriters: true,
		IncludeData:       true,
	})
	if err != nil {
		t.Errorf("Error %s listing records for client %+v\n", err, sharee)
	}
	var found bool
	var encryptedSharedRecord pdsClient.Record
	for _, record := range listResponse.Results {
		if record.Metadata.RecordID == createdRecord.Metadata.RecordID {
			found = true
			encryptedSharedRecord.Data = record.Data
			encryptedSharedRecord.Metadata = record.Metadata
			break
		}
	}
	if !found {
		t.Fatalf("Failed to find shared records in list records results %+v\n", listResponse)
	}
	decryptedRecord, err := sharee.DecryptRecord(ctx, encryptedSharedRecord)
	if err != nil {
		t.Fatalf("error %s decrypting record %+v", err, encryptedSharedRecord)
	}
	if decryptedRecord.Data[dataKeyToEncrypt] != data[dataKeyToEncrypt] {
		t.Errorf("expected shared encrypted record decrypted data to be %+v, got %+v", data, decryptedRecord)
	}
}

func TestSharedReadersFoundAfterSharingRecords(t *testing.T) {
	// Create a client to share records with
	sharee, shareeID, _, err := test.CreatePDSClient(testContext, toznyCyclopsHost, e3dbClientHost, validPDSRegistrationToken, fmt.Sprintf("test+pdsClient+%d@tozny.com", uuid.New()), defaultPDSUserRecordType)
	if err != nil {
		t.Errorf("Error creating client to share records with: %s", err)
	}
	// Share records of type created with sharee client
	ctx := context.TODO()
	err = validPDSUser.ShareRecords(ctx, pdsClient.ShareRecordsRequest{
		UserID:     validPDSUserID,
		WriterID:   validPDSUserID,
		ReaderID:   shareeID,
		RecordType: defaultPDSUserRecordType,
	})
	if err != nil {
		t.Errorf("Error %s sharing records of type %s with client %+v\n", err, defaultPDSUserRecordType, sharee)
	}
	// Create records to share with this client
	data := map[string]string{"data": "unencrypted"}
	recordToWrite := pdsClient.WriteRecordRequest{
		Data: data,
		Metadata: pdsClient.Meta{
			Type:     defaultPDSUserRecordType,
			WriterID: validPDSUserID,
			UserID:   validPDSUserID,
			Plain:    map[string]string{"key": "value"},
		},
	}
	_, err = validPDSUser.WriteRecord(ctx, recordToWrite)
	if err != nil {
		t.Errorf("Error writing record to share %s\n", err)
	}

	allowedReadsRequest := pdsClient.InternalAllowedReadersForPolicyRequest{
		WriterID:    validPDSUserID,
		ContentType: defaultPDSUserRecordType,
	}
	resp, err := bootInternalPDSClient.InternalAllowedReadsForAccessPolicy(ctx, allowedReadsRequest)
	if err != nil {
		t.Errorf("Error trying to call PDS for allowed readers %s\n", err)
	}
	var foundSharee bool
	for _, readerID := range resp.ReaderIDs {
		if readerID == shareeID {
			foundSharee = true
			break
		}
	}
	if !foundSharee {
		t.Errorf("Could not find sharee id in list of allowed readers for record\n")
	}
}

func TestDeleteRecord(t *testing.T) {
	// Create record to delete
	ctx := context.TODO()
	data := map[string]string{"data": "unencrypted"}
	recordToWrite := pdsClient.WriteRecordRequest{
		Data: data,
		Metadata: pdsClient.Meta{
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
	deleteRequest := pdsClient.DeleteRecordRequest{
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
	recordToWrite := pdsClient.WriteRecordRequest{
		Data: data,
		Metadata: pdsClient.Meta{
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

	modifiedRecordRequest := pdsClient.InternalSearchRequest{
		NextToken: 0,
		Range: &pdsClient.InternalModifiedRange{
			After:  startTime,
			Before: endTime,
		},
	}
	modifiedResponse, err := bootInternalPDSClient.InternalSearch(ctx, modifiedRecordRequest)
	if err != nil {
		t.Fatalf("Error getting modified records %s\n", err)
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

func TestAddAuthorizedAllowsAuthorizerToShareAuthorizedRecordTypes(t *testing.T) {
	// Create authorizing account and client
	clientConfig, authorizingAccount, err := test.MakeE3DBAccount(t, &bootAccountClient, uuid.New().String(), e3dbAuthHost)
	if err != nil {
		t.Errorf("Unable to create authorizing client using %+v", bootAccountClient)
	}
	clientConfig.Host = toznyCyclopsHost
	authorizingClient := pdsClient.New(clientConfig)
	authorizingClientID := authorizingAccount.Account.Client.ClientID
	// Setup authorizing client to be able to write records of a given type
	_, err = test.MakeClientWriterForRecordType(authorizingClient, authorizingClientID, defaultPDSUserRecordType)
	// Create records to for authorizer to share
	ctx := context.TODO()
	data := map[string]string{"data": "unencrypted"}
	recordToWrite := pdsClient.WriteRecordRequest{
		Data: data,
		Metadata: pdsClient.Meta{
			Type:     defaultPDSUserRecordType,
			WriterID: authorizingClientID,
			UserID:   authorizingClientID,
			Plain:    map[string]string{"key": "value"},
		},
	}
	createdRecord, err := authorizingClient.WriteRecord(ctx, recordToWrite)
	if err != nil {
		t.Errorf("Error %s writing record to share %+v\n", err, recordToWrite)
	}
	// Create authorizer account and client
	clientConfig, authorizerAccount, err := test.MakeE3DBAccount(t, &bootAccountClient, uuid.New().String(), e3dbAuthHost)
	if err != nil {
		t.Errorf("Unable to create authorizer client using %+v", bootAccountClient)
	}
	clientConfig.Host = toznyCyclopsHost
	authorizerClient := pdsClient.New(clientConfig)
	authorizerClientID := authorizerAccount.Account.Client.ClientID
	// Create account and client for authorizer to share records with
	clientConfig, shareeAccount, err := test.MakeE3DBAccount(t, &bootAccountClient, uuid.New().String(), e3dbAuthHost)
	if err != nil {
		t.Errorf("Unable to create authorizer client using %+v", bootAccountClient)
	}
	clientConfig.Host = toznyCyclopsHost
	shareeClient := pdsClient.New(clientConfig)
	shareeAccountID := shareeAccount.Account.Client.ClientID
	// Authorize the authorizer for sharing records
	authorizeRequest := pdsClient.AddAuthorizedWriterRequest{
		UserID:       authorizingClientID,
		WriterID:     authorizingClientID,
		AuthorizerID: authorizerClientID,
		RecordType:   defaultPDSUserRecordType,
	}
	err = authorizingClient.AddAuthorizedSharer(ctx, authorizeRequest)
	if err != nil {
		t.Errorf("Error %s for %+v trying to make authorize request with params %+v", err, authorizingClient, authorizeRequest)
	}
	// Authorizer share record type they have been authorized to share
	err = authorizerClient.AuthorizerShareRecords(ctx, pdsClient.AuthorizerShareRecordsRequest{
		UserID:       authorizingClientID,
		WriterID:     authorizingClientID,
		AuthorizerID: authorizerClientID,
		ReaderID:     shareeAccountID,
		RecordType:   defaultPDSUserRecordType,
	})
	if err != nil {
		t.Errorf("Error %s sharing records of type %s with client %+v\n", err, defaultPDSUserRecordType, shareeAccountID)
	}
	// Verify sharee can retrieve shared record
	listRecordsResponse, err := shareeClient.ListRecords(ctx, pdsClient.ListRecordsRequest{
		ContentTypes:      []string{defaultPDSUserRecordType},
		IncludeAllWriters: true,
		IncludeData:       true})
	if err != nil {
		t.Errorf("Error %s listing records for %+v", err, shareeClient)
	}
	var found bool
	for _, listedRecord := range listRecordsResponse.Results {
		if listedRecord.Metadata.RecordID == createdRecord.Metadata.RecordID {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Failed to find record %+v that should be shared, got %+v", createdRecord, listRecordsResponse.Results)
	}
}

func TestServiceHealthCheckReturnsSuccessIfPDSIsRunning(t *testing.T) {
	ctx := context.TODO()
	err := validPDSUser.HealthCheck(ctx)
	if err != nil {
		t.Errorf("Expected pds health check to return no error, got %s", err)
	}
}

func TestInternalSearchAllowedReads(t *testing.T) {
	// Create a client to share records with
	sharee, shareeID, _, err := test.CreatePDSClient(testContext, toznyCyclopsHost, e3dbClientHost, validPDSRegistrationToken, fmt.Sprintf("test+pdsClient+%d@tozny.com", uuid.New()), defaultPDSUserRecordType)
	if err != nil {
		t.Errorf("Error creating client to share records with: %s", err)
	}
	// Share records of type created with sharee client
	ctx := context.TODO()
	startTime := time.Now().UTC()
	share := pdsClient.ShareRecordsRequest{
		UserID:     validPDSUserID,
		WriterID:   validPDSUserID,
		ReaderID:   shareeID,
		RecordType: defaultPDSUserRecordType,
	}
	err = validPDSUser.ShareRecords(ctx, share)
	endTime := time.Now().AddDate(0, 0, 1).UTC()
	if err != nil {
		t.Errorf("Error %s sharing records of type %s with client %+v\n", err, defaultPDSUserRecordType, sharee)
	}
	record, err := test.WriteRandomRecordForUser(validPDSUser, defaultPDSUserRecordType, validPDSUserID, nil, nil)
	if err != nil {
		t.Errorf("Unable to write record for PDS User %s", err)
	}
	// Verify the new allowed_read is visible to the internal client
	searchAllowedReadsRequest := pdsClient.InternalSearchAllowedReadsRequest{
		NextToken: 0,
		Range: &pdsClient.InternalModifiedRange{
			After:  startTime,
			Before: endTime,
		},
	}
	searchResponse, err := bootInternalPDSClient.InternalSearchAllowedReads(ctx, searchAllowedReadsRequest)
	if err != nil {
		t.Fatalf("Error searching allowed_reads %s\n", err)
	}
	found := false
	for _, allowedRead := range searchResponse.AllowedReads {
		if allowedRead.UserID == share.UserID && allowedRead.WriterID == share.WriterID && allowedRead.ContentType == share.RecordType {
			found = true
		}
	}
	if !found {
		t.Errorf("Could not find newly added allowed read %+v\n in list of recently added allowed reads %+v\n we wrote record %+v", share, searchResponse, record)
	}
}

func TestInternalSearchUsingRecordType(t *testing.T) {
	// Create record to with an external client
	recordType := "TestInternalSearchUsingRecordType"
	_, err := test.MakeClientWriterForRecordType(validPDSUser, validPDSUserID, recordType)
	if err != nil {
		t.Errorf("error %s making client %+v a writer for record type %s", err, validPDSUser, recordType)
	}
	data := map[string]string{"data": "unencrypted"}
	recordToWrite := pdsClient.WriteRecordRequest{
		Data: data,
		Metadata: pdsClient.Meta{
			Type:     recordType,
			WriterID: validPDSUserID,
			UserID:   validPDSUserID,
			Plain:    map[string]string{"key": "value"},
		},
	}
	ctx := context.Background()
	wroteRecord, err := validPDSUser.WriteRecord(ctx, recordToWrite)
	if err != nil {
		t.Errorf("Error %s writing record %+v\n", err, recordToWrite)
	}
	// Verify we can do an internal search based off the record type
	searchRequest := pdsClient.InternalSearchRequest{
		ContentTypes: []string{recordType},
	}
	searchResponse, err := bootInternalPDSClient.InternalSearch(ctx, searchRequest)
	if err != nil {
		t.Errorf("Error %s searching records\n", err)
	}
	var found bool
	for _, record := range searchResponse.Records {
		if record.Metadata.RecordID == wroteRecord.Metadata.RecordID {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected to find record %+v\n in search results %+v\n", wroteRecord, searchResponse.Records)
	}
}

func TestInternalSearchByWriterId(t *testing.T) {
	// Create record to with an external client
	recordType := "TestInternalSearchUsingUUID"
	_, err := test.MakeClientWriterForRecordType(validPDSUser, validPDSUserID, recordType)
	if err != nil {
		t.Errorf("error %s making client %+v a writer for record type %s", err, validPDSUser, recordType)
	}
	data := map[string]string{"data": "unencrypted"}
	recordToWrite := pdsClient.WriteRecordRequest{
		Data: data,
		Metadata: pdsClient.Meta{
			Type:     recordType,
			WriterID: validPDSUserID,
			UserID:   validPDSUserID,
			Plain:    map[string]string{"key": "value"},
		},
	}
	ctx := context.Background()
	wroteRecord, err := validPDSUser.WriteRecord(ctx, recordToWrite)
	if err != nil {
		t.Errorf("Error %s writing record %+v\n", err, recordToWrite)
	}
	// Verify we can do an internal search based off the record type
	searchRequest := pdsClient.InternalSearchRequest{
		WriterIDs: []string{validPDSUserID},
	}
	searchResponse, err := bootInternalPDSClient.InternalSearch(ctx, searchRequest)
	if err != nil {
		t.Errorf("Error %s searching records\n", err)
	}
	var found bool
	for _, record := range searchResponse.Records {
		if record.Metadata.RecordID == wroteRecord.Metadata.RecordID {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected to find record %+v\n in search results %+v\n", wroteRecord, searchResponse.Records)
	}
}
