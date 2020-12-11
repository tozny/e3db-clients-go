package storageClient_test

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	e3dbClients "github.com/tozny/e3db-clients-go"
	"github.com/tozny/e3db-clients-go/accountClient"
	"github.com/tozny/e3db-clients-go/pdsClient"
	storageClientV2 "github.com/tozny/e3db-clients-go/storageClient"
	"github.com/tozny/e3db-clients-go/test"
)

var (
	cyclopsServiceHost = os.Getenv("TOZNY_CYCLOPS_SERVICE_HOST")
	testCtx            = context.Background()
	ClientServiceHost  = os.Getenv("CLIENT_SERVICE_HOST")
)

func TestFullSignatureAuthenticationFlowSucceedsNoUID(t *testing.T) {
	// Make request through cyclops to test tozny header is parsed properly
	registrationClient := accountClient.New(e3dbClients.ClientConfig{Host: cyclopsServiceHost}) // empty account host to make registration request
	queenClientConfig, _, err := test.MakeE3DBAccount(t, &registrationClient, uuid.New().String(), cyclopsServiceHost)
	if err != nil {
		t.Fatalf("Could not register account %s\n", err)
	}
	queenClientConfig.Host = cyclopsServiceHost
	queenClientConfig.ClientID = "" // remove clientID
	storageServiceClient := storageClientV2.New(queenClientConfig)
	noteToWrite, err := generateNote(queenClientConfig.SigningKeys.Public.Material, queenClientConfig)
	if err != nil {
		t.Fatalf("unable to generate note with config %+v\n", queenClientConfig)
	}
	_, err = storageServiceClient.WriteNote(testCtx, *noteToWrite)
	if err != nil {
		t.Errorf("unable to write note %+v, to storage service %s\n", noteToWrite, err)
	}
}

func TestFullSignatureAuthenticationFlowSucceedsWithUID(t *testing.T) {
	// Make request through cyclops to test tozny header is parsed properly
	registrationClient := accountClient.New(e3dbClients.ClientConfig{Host: cyclopsServiceHost}) // empty account host to make registration request
	queenClientConfig, _, err := test.MakeE3DBAccount(t, &registrationClient, uuid.New().String(), cyclopsServiceHost)
	if err != nil {
		t.Fatalf("Could not register account %s\n", err)
	}
	StorageClient := storageClientV2.New(queenClientConfig)
	noteToWrite, err := generateNote(queenClientConfig.SigningKeys.Public.Material, queenClientConfig)
	if err != nil {
		t.Fatalf("unable to generate note with config %+v\n", queenClientConfig)
	}
	_, err = StorageClient.WriteNote(testCtx, *noteToWrite)
	if err != nil {
		t.Errorf("unable to write note %+v, to storage service %s\n", noteToWrite, err)
	}
}

func TestAddTozIDEACPWhenCreatingNote(t *testing.T) {
	// Make request through cyclops to test tozny header is parsed properly
	registrationClient := accountClient.New(e3dbClients.ClientConfig{Host: cyclopsServiceHost}) // empty account host to make registration request
	queenClientConfig, _, err := test.MakeE3DBAccount(t, &registrationClient, uuid.New().String(), cyclopsServiceHost)
	if err != nil {
		t.Fatalf("Could not register account %s\n", err)
	}
	StorageClient := storageClientV2.New(queenClientConfig)
	noteToWrite, err := generateNote(queenClientConfig.SigningKeys.Public.Material, queenClientConfig)

	if err != nil {
		t.Fatalf("unable to generate note with config %+v\n", queenClientConfig)
	}
	noteToWrite.EACPS = &storageClientV2.EACP{
		TozIDEACP: &storageClientV2.TozIDEACP{
			RealmName: "someRealm",
		},
	}
	writtenNote, err := StorageClient.WriteNote(testCtx, *noteToWrite)
	if err != nil {
		t.Errorf("unable to write note with TozIDEACP %+v, to storage service %s\n ", noteToWrite, err)
	}
	if writtenNote.EACPS == nil || writtenNote.EACPS.TozIDEACP == nil {
		t.Fatalf("expected non nil TozIDEACP for note EACPS, got %+v", writtenNote.EACPS)
	}
}

func generateNote(recipientSigningKey string, clientConfig e3dbClients.ClientConfig) (*storageClientV2.Note, error) {
	rawData := map[string]string{
		"key1": "rawnote",
		"key2": "unprocessednote",
		"key3": "organicnote",
	}
	ak := e3dbClients.RandomSymmetricKey()
	eak, err := e3dbClients.EncryptAccessKey(ak, clientConfig.EncryptionKeys)
	if err != nil {
		return nil, err
	}
	encryptedData := e3dbClients.EncryptData(rawData, ak)

	return &storageClientV2.Note{
		Mode:                "Sodium",
		RecipientSigningKey: recipientSigningKey,
		WriterSigningKey:    clientConfig.SigningKeys.Public.Material,
		WriterEncryptionKey: clientConfig.EncryptionKeys.Public.Material,
		EncryptedAccessKey:  eak,
		Type:                "Integration Test",
		Data:                *encryptedData,
		Plain:               map[string]string{"extra1": "not encrypted", "extra2": "more plain data"},
		Signature:           "signed",
		MaxViews:            5,
	}, err
}

// Currently write file is split between storage v1 and storage v2 endpoints
func TestWriteFileAsDeployed(t *testing.T) {
	// Create account, pds & storage clients
	registrationClient := accountClient.New(e3dbClients.ClientConfig{Host: cyclopsServiceHost}) // empty account host to make registration request
	queenClientConfig, _, err := test.MakeE3DBAccount(t, &registrationClient, uuid.New().String(), cyclopsServiceHost)
	if err != nil {
		t.Fatalf("Could not register account %s\n", err)
	}
	storageClient := storageClientV2.New(queenClientConfig)
	pdsServiceClient := pdsClient.New(queenClientConfig)
	clientID := queenClientConfig.ClientID
	// Create an access key to allow for decrypting
	// records of this type
	recordType := "test2"
	putEAKParams := pdsClient.PutAccessKeyRequest{
		WriterID:           clientID,
		UserID:             clientID,
		ReaderID:           clientID,
		RecordType:         recordType,
		EncryptedAccessKey: "SOMERANDOMNPOTENTIALLYNONVALIDKEY",
	}
	_, err = pdsServiceClient.PutAccessKey(testCtx, putEAKParams)
	if err != nil {
		t.Errorf("Error trying to put access key for %+v %s", clientID, err)
	}

	// Create file and compute its signature
	fileValue := "It was the best of times. It was the worst of times."
	hasher := md5.New()
	fileLength, err := io.WriteString(hasher, fileValue)
	if err != nil {
		t.Fatalf("Could not write to hasher %+v", err)
	}
	hashString := base64.StdEncoding.EncodeToString(hasher.Sum(nil))
	// Initiate the request to create a file
	clientUUID, err := uuid.Parse(clientID)
	if err != nil {
		t.Fatalf("%s Could not parse string client id %s to uuid", err, clientID)
	}
	fileRecordToWrite := storageClientV2.Record{
		Metadata: storageClientV2.Meta{
			WriterID: clientUUID,
			UserID:   clientUUID,
			Type:     recordType,
			Plain: map[string]string{
				"key": "value",
			},
			FileMeta: &storageClientV2.FileMeta{
				Size:     fileLength,
				Checksum: hashString,
			},
		},
	}
	pendingFileURL, err := storageClient.WriteFile(testCtx, fileRecordToWrite)
	if err != nil {
		t.Fatalf("Call to file post should return 200 level status code returned %+v", err)
	}
	// Write the file to the server directed location
	req, err := http.NewRequest("PUT", pendingFileURL.FileURL, strings.NewReader(fileValue))
	req.Header.Set("Content-MD5", hashString)
	req.Header.Set("Content-Type", "application/octet-stream")
	if err != nil {
		t.Fatalf("Creation of put request should not cause an error")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
		t.Fatalf("Put to pendingFileURL with presigned URL should not error %+v resp %+v", err, resp)
	}
	// Register the file as being written
	_, err = pdsServiceClient.FileCommit(testCtx, pendingFileURL.PendingFileID.String())
	if err != nil {
		t.Fatalf("Pending file commit should not fail for file that has been loaded to datastore %+v", err)
	}
}

func TestWriteFileWithBigMetadataKey(t *testing.T) {
	// Create account, pds & storage clients
	registrationClient := accountClient.New(e3dbClients.ClientConfig{Host: cyclopsServiceHost}) // empty account host to make registration request
	queenClientConfig, _, err := test.MakeE3DBAccount(t, &registrationClient, uuid.New().String(), cyclopsServiceHost)
	if err != nil {
		t.Fatalf("Could not register account %s\n", err)
	}
	storageClient := storageClientV2.New(queenClientConfig)
	pdsServiceClient := pdsClient.New(queenClientConfig)
	clientID := queenClientConfig.ClientID
	// Create an access key to allow for decrypting
	// records of this type
	recordType := "test2"
	putEAKParams := pdsClient.PutAccessKeyRequest{
		WriterID:           clientID,
		UserID:             clientID,
		ReaderID:           clientID,
		RecordType:         recordType,
		EncryptedAccessKey: "SOMERANDOMNPOTENTIALLYNONVALIDKEY",
	}
	_, err = pdsServiceClient.PutAccessKey(testCtx, putEAKParams)
	if err != nil {
		t.Errorf("Error trying to put access key for %+v %s", clientID, err)
	}

	// Create file and compute its signature
	fileValue := "It was the best of times. It was the worst of times."
	hasher := md5.New()
	fileLength, err := io.WriteString(hasher, fileValue)
	if err != nil {
		t.Fatalf("Could not write to hasher %+v", err)
	}
	hashString := base64.StdEncoding.EncodeToString(hasher.Sum(nil))
	// Initiate the request to create a file
	clientUUID, err := uuid.Parse(clientID)
	if err != nil {
		t.Fatalf("%s Could not parse string client id %s to uuid", err, clientID)
	}
	longMetadataValueThatFailedBefore := "f9b45d1b-e2a6-41bb-bc24-1752bfb3b225,d60dd485-af5b-4154-bf82-e5819d876564,43f7e5d3-4630-4c8a-ac69-9f224617c636,bc34c096-4144-4d30-8e97-0c514bc553ac,3f364a9b-a6cf-49ef-b095-40d028ad9544,be62e57d-bee8-41ec-b68f-63441109a390,ae87497d-6d86-48bb-a066-4843aaf73bf0,0249e308-1ffd-4f6a-b49f-cdde8a1e02eb,b729fe90-60c0-40a5-99f2-fab8878e64bd,2bd038d4-4375-47e8-b106-b3b3d0a3eb0f,52052e2e-79e6-4921-9dd2-409a06354a5b,dc552efb-0b26-4c80-b748-69ed51f059d6,0cd6efe7-00e4-4788-97a3-3cfb0d524844,1030f06c-a8d3-4b58-945e-6e00b491b007,0addefd0-827c-405d-9d79-59d6b489908e,7a4cb5ba-1695-4975-bbaa-755431b94571,f0a9d3da-a3a1-494f-ab15-cec3b2f00ef5,e80dab93-3904-4f1c-820b-250fc08948fc,0bd0c6e5-d569-4b84-84b7-22ff280b1efe,57b9211b-2ee6-4240-a5f5-3a0751e094a6,43e0a9fc-ccbd-4a37-b889-2efb89796873,c11601ee-a136-4de7-b754-96571e98a88f,1a01609a-3075-44c7-b954-38c12d0388fd,86c4a8c6-4492-46d1-8e59-de5865271d53,67e5cdba-111f-4ec3-9c9d-576b4fe13318,bbe7a19f-df87-4cad-8ae2-2dba51ce5914,12de1741-4a06-4df7-b76b-6993f48e7bab,a4a3e869-59a0-4888-a264-25927ef334da,62f9339b-58a7-4f94-a6da-cb3d8fa1e045,70cacaeb-0ec5-4362-a75c-1f2f507995d4,28896cdf-7c8b-43f2-a7ad-62cfffa83575,f6ee6580-e989-4a7b-9162-c4ffba211958,342b43b4-3a0d-4a5c-966c-a64e337e1703,ceb609a6-50d2-4560-8c18-23ee7457c1ae,bef0eb8e-b97a-4cfc-98fe-499929b87edf,36113c71-d05b-4a07-a8b5-9aea9e3e4231,10338185-c164-4642-ac8d-aed84a7b51dd,985e73c8-2797-4625-a76d-e8dbd0fb559a,4788188b-6a7e-4e43-937f-819789dae5aa,f137eb97-603e-4b30-be1e-c458643335db,2fba1530-caca-427f-a89f-636f0c6ef598,b9827ea1-6a4b-49e9-b462-93e4eb2acaaf,dc88dafb-cf00-4d82-a10c-9db205f412e5,77d4e00c-d088-4f0e-b5b3-e469ce1a6144,71b00bbf-5b16-446b-8f6b-246a1600c5d3,06d63e92-8b63-4a20-8d42-e3163e38ad32,5d1afd7f-e7ec-4125-bb6e-896959e2bfd6,7fd4e389-3328-49b4-b9d3-2ff08ae85905,a8750eeb-dd8f-4814-949c-9af405d82702,e6c0b8b8-8685-4752-8903-f226ab8c3a80,fd4ce118-2638-4daa-869d-60e1c5088318,9f9206e1-9783-48ca-bcfe-4eca08a4a21f,a1ceeb2b-d826-46c0-bc1a-1704d0bb7f81,48a2f3b6-72cf-4949-859a-2afc04b7f0ad,8382e564-9265-4503-8eb9-558b470ede4d,0c70493c-cf41-4141-a676-217f64b1a46d,81693c9e-d14e-4105-adde-1af29ac8ab91,a1319008-93b5-42ef-beae-6998f4aef7ca,1627f2dd-357d-4b86-be2d-2b48f06eaae6,9df28879-9749-4e7a-b103-a56be01f3784,505c1a3b-6722-443c-8b99-4096919f6349,68d9b072-32c1-4068-9c5a-50ee99e74c28,a24b5628-517c-4076-a9c7-fa20c04111b4,04086f27-11b6-4034-b42a-898b511763cf,3b28bb59-9747-4e8a-baf7-3ee2589d4c45,52a1feb1-dbdd-49a4-8806-80a4b17a789d,90694b91-dfd4-4e3c-a4fc-e60e66e29015,bb1f1760-6c54-4b8f-ac62-39e5d395437a,3738daa7-600b-495f-99ed-c4cb40735e8a,19ad12a0-ba06-4327-a229-ba59d021e1a8,61f8f6e6-a507-4aee-a92a-340f597ca090,670e4888-cad7-4176-8f03-a8945575972f,2afacccd-de6f-491d-a795-674b67448ab1,7ce8616b-4545-42c3-8938-bf852f7596a0,93d6c634-f7a1-4e33-a86e-2be136c9ffca,9ecc068f-115b-43a2-bdf5-eb31b5ea284a,5c6958ce-2713-4fbc-a7b0-70a47b33b3f7,3f2919e2-182b-429a-89e1-2f7ffbbbd465,06d44f7d-715e-47b1-b411-cb4d21dba39e,ef7a8c29-2b20-434c-aa05-8841923d2740,b3d73cfa-a82c-4b4d-a6cb-0e1563d4b19d,249d8fdc-0438-412a-84be-caa2d5b300f1,b5502311-ac0a-4862-bcfc-043cdd5a348f,daaad6f1-3b9c-4891-baa1-08eb4c200bf3,0b9533f1-fe92-4805-bf89-e036fd630c1e,797b2ae2-94ca-4761-bf4c-180e147702ea,b316bb0d-846d-4955-a596-809b51e3e93d,3331f1b1-33b3-1d31-11a3-236d1aa3a1c3,a9236169-d7af-40d9-84dd-0cdb96bde54a,dc003cc6-b80d-49c6-b501-ce3a14ed2a64,fcbd98d5-7caf-472e-9768-2ab2073dbe32,8381785a-78e6-4c52-8525-b716bc706e94,d6c2962d-0c98-4317-ac8f-4b06a1c0489d,c752e9da-0fff-455b-8cd7-f95b23e66f35,0a6e2130-29e4-4cf8-a5c1-a2082237ccbf,9263a22f-4698-4baf-bab9-c24f2a0f932c,08a6c81b-f47a-4a9e-a1b0-7053bd6df02b,35e0d499-42c0-4e3e-9741-fdfa238baef9,7c8d87cb-cc97-42ac-ad21-119819501e5c,18f10e7d-2a6f-4b55-a244-001f4c464811,f1ec4f8b-9a2c-4818-8b0c-9852a722ea03,15f8134a-57ff-4aa8-8eee-c9b6c5a2dc52,c9261f75-9851-41fc-9112-84e6139b7dc4,8b3b4115-808f-43c5-9a1d-6dfac0a156a7,1cf64438-9d5e-4b2c-8cbc-ca023d78fd82,723beea3-0de5-4d61-bc20-24c6012f6e9e,f0f8b154-f32d-4ccc-b252-33283b5d6fa7,71076f7c-1d33-4f17-b58c-e84cfc48ff31,d3dfab27-7f58-4139-9e30-18e486adecdb,1331f1b1-33b3-1d31-11a3-236d1aa3a1c3,ad7ee026-e08a-4f73-ad11-7d3128af0633,e1955652-d0fd-44e5-a2db-0420ee2ec621,0bd4bd99-fb2b-426e-810b-64466bed6980,6215decf-751d-4da0-bdc7-c4071ec43621,bf3d5309-a356-49ca-8be9-320661a4dc7d,ea2c3cfa-c429-479b-a3c9-20b8b4879f05,4c5b531f-eab3-4a55-8e59-285945f23629,44414d4d-a511-4b43-95a3-592d30027ca0,4c5b531f-eab3-4a55-8e59-285945f23629,44414d4d-a511-4b43-95a3-592d30027ca0,77c47e2b-118b-43be-80f2-17bb9c9b834d,39962154-ff5b-4114-bed7-63a3f16943ff,dfa62ecf-9578-4e3b-a254-7e76abe0cce8,4a0aca83-5990-4236-83d1-645d4c1e880e,4b479f5b-49f7-4c54-b33a-e3edfa7fa865,a70563e8-a3cc-421b-9d7b-ec64c28dcf7b,58d532bd-6f63-41b7-988a-7a3bcad58676,3dcc416b-73ef-4a28-bbbb-6af6de6710e1,bf5361e3-c415-49b4-bc24-1ffaf6f7e43f,9dc11d2a-ffcb-4d22-8486-cf64bd888ede,11f90723-ae72-4691-9090-4752b5d828dc,21fd1ce4-d68e-4286-ad6f-89371f4061d9,efa485fa-a610-478b-a637-49847d3e0daa,c53e1de2-9a8e-4db3-9f5d-2aa9debc407a,7731f1b1-33b3-1d31-11a3-236d1aa3a1c3,b5c67892-9f8e-4459-8c53-dcfb720c4ace,c1508e81-1a19-44eb-8c03-464a2f9a1418,1cdfaa66-3df1-448d-9c70-b004bd8f300c,88689fb5-365d-4341-9555-e3290216662f,0d87cbe4-5775-4c22-9de4-8967a4dc6a70,242b0ee0-2bde-43d6-ab20-6dd9ca138964,edb96bcc-e0bd-404e-b999-291917c6e18d,3331f1b1-32b3-1d22-11a3-322d1aa3a1c3,3431b2f9-d899-4323-ae95-395e0d104411,3318ecbe-5719-4730-93e4-8eec664d2817,e0dd918a-fb39-499a-88ac-3a68ccd99c3b,958e4721-c438-493d-9909-693ff60a3ef0,ab6c11c3-45f9-4fcb-8872-12353bb7e547,7f9b36c9-7cf6-4b8a-be37-37e9ab9b63c2,35806e73-6177-4759-b0a3-6b77ecca700d,6599267e-d1da-438b-8dde-816636cdea7b,495d6492-a848-42fc-b7d5-b19514d726d7,adaad6f3-eba6-439a-a6d4-fdbebb406801,bc16d08a-7bfa-45f6-aedd-6c63263163a6,b9c16d78-1138-4a76-af84-51992b888a82,ded734d2-c935-4508-92c5-2202a7665e93,b7e744d9-e334-475e-bc0b-be29fd91075e,e7ed849a-04d8-4b8d-a8a0-2f225e2726bf,ed3cb8a1-aff3-4502-933c-c97ca24692ed,83af7bf6-1aff-4e43-a5c2-6b138a1621f4,3221f1b1-33b3-1d31-22a3-236d1aa3a1c3,15d4b11f-2fe6-47cc-93b2-d8fac392e3c0,cd70e1d0-6ce8-4af4-b257-17300d7e1f8e,543daf0e-117d-42f5-8ee5-77fd9178bd89,7b4fe709-4fdb-41eb-885d-fee5ce257a9a,eb75759a-3c78-4efc-be16-443b50a7c582,3431b2f9-d858-4533-ae95-395e0d104410,c3390494-994f-47d1-a2da-f275a1ab4683,0309a247-c8a7-4011-8e18-29bdb093b757,e076a197-8ddf-4135-9ac7-641f5f326935,6f4ec66d-6ac9-4752-93fd-99c68f9b3544,313327e7-9b64-4f55-bd69-17bc0a0bd216,c659e296-aa1d-48e1-8b07-2f4f785bc9f1,3ff2f0a3-4840-4f77-aac0-978e6cd32ac7,c1505bc6-f16d-4a0b-93d9-fb19cddf06e2,368a7439-ae2b-4106-9a38-accea578debc,3bb76054-f185-4542-a18e-f645b37feee2,46ec26fb-f474-40d4-9d4d-836b4b24ac0d,fa3fe2cf-a45a-46d8-b26a-802686366ebc,86be9334-ac79-4d38-b85c-c592fa61dc58,21377d42-20cf-453d-9cd6-f8a21d14b76f,a759edf9-b33b-4c4f-9b59-cf6caee576b9,795b1800-eb56-456f-9f1c-d961a294aafa,6fb6b177-362f-46b2-a14a-e41261a2951a,2231f1b1-33b3-1d31-15a3-236d1aa3a1c3,d94ed947-ba1b-4841-ae6e-cc7a0f323a2a,c2ae0c92-f6d2-4c39-9b1b-a4fb4da220fb,15ba7873-6dd4-4c2f-9268-975ea15c28a6,917bab37-b92f-4d64-8bf8-6d2b50a80039,d94b62f7-6ab7-4ef6-b57c-ec774d71fa18,25c485c2-dae0-448a-918a-e815b3bdfdc6,c367bb95-5cfa-4af2-9294-8493684a85a5,05541de1-9506-4feb-b2af-7914ceb3bd66,9afe6486-e794-4b9b-80a1-7c3e27270aea,51204faf-c7fd-4197-ae50-ca86ef6e886f,955a4509-2554-482c-9c7a-376d8c2ac0b1,502a0a45-9739-4ba8-9e84-268134d0999f,25524c4c-037b-4c3a-a771-6778b300f2b1,584da3d7-cdd6-458e-bd23-1e7de6cfe22d,74f6f885-c421-4106-8d16-fd32bf313637,7d239c06-cde7-40af-889d-fc3a8223de9d,bb002c44-cb90-4bf6-9cf2-6bebac5b6b50,8085b2ae-07e5-4768-b3b2-ebaa2afd6a7e,d0c27250-4cc5-488f-9d4a-7ba6f5c4e5fb,a6a3992a-2c3b-43d3-9e0e-9728597ddbc5,ed2d1469-3d06-45a1-bb49-de7b14cd26ea,80de8aa-0bee-4ee8-bbb2-eaff5af1b171,6ab2d9c8-66b8-4c3a-bab5-2e8544fc52d8,0062f5b2-56b5-48d9-ae17-b80c69f936fd,27e95a6d-25a8-40ca-96f5-c43b7f22ba34,85be1fd6-3711-42e7-927d-c002c461b9a7,95f6dd2b-134d-48aa-b177-57d84b970168,b306ba7f-e4f6-4810-b660-bb8272374849,670e4888-cad7-4176-8f03-a8945575972f,2afacccd-de6f-491d-a795-674b67448ab1,7ce8616b-4545-42c3-8938-bf852f7596a0,93d6c634-f7a1-4e33-a86e-2be136c9ffca,9ecc068f-115b-43a2-bdf5-eb31b5ea284a,5c6958ce-2713-4fbc-a7b0-70a47b33b3f7,3f2919e2-182b-429a-89e1-2f7ffbbbd465,06d44f7d-715e-47b1-b411-cb4d21dba39e,ef7a8c29-2b20-434c-aa05-8841923d2740,b3d73cfa-a82c-4b4d-a6cb-0e1563d4b19d,249d8fdc-0438-412a-84be-caa2d5b300f1,b5502311-ac0a-4862-bcfc-043cdd5a348f,daaad6f1-3b9c-4891-baa1-08eb4c200bf3,0b9533f1-fe92-4805-bf89-e036fd630c1e,797b2ae2-94ca-4761-bf4c-180e147702ea,b316bb0d-846d-4955-a596-809b51e3e93d,3331f1b1-33b3-1d31-11a3-236d1aa3a1c3,a9236169-d7af-40d9-84dd-0cdb96bde54a,dc003cc6-b80d-49c6-b501-ce3a14ed2a64,fcbd98d5-7caf-472e-9768-2ab2073dbe32,8381785a-78e6-4c52-8525-b716bc706e94,d6c2962d-0c98-4317-ac8f-4b06a1c0489d,c752e9da-0fff-455b-8cd7-f95b23e66f35,0a6e2130-29e4-4cf8-a5c1-a2082237ccbf,9263a22f-4698-4baf-bab9-c24f2a0f932c,08a6c81b-f47a-4a9e-a1b0-7053bd6df02b,35e0d499-42c0-4e3e-9741-fdfa238baef9,7c8d87cb-cc97-42ac-ad21-119819501e5c,18f10e7d-2a6f-4b55-a244-001f4c464811,f1ec4f8b-9a2c-4818-8b0c-9852a722ea03,15f8134a-57ff-4aa8-8eee-c9b6c5a2dc52,c9261f75-9851-41fc-9112-84e6139b7dc4,8b3b4115-808f-43c5-9a1d-6dfac0a156a7,1cf64438-9d5e-4b2c-8cbc-ca023d78fd82,723beea3-0de5-4d61-bc20-24c6012f6e9e,f0f8b154-f32d-4ccc-b252-33283b5d6fa7,71076f7c-1d33-4f17-b58c-e84cfc48ff31,d3dfab27-7f58-4139-9e30-18e486adecdb,1331f1b1-33b3-1d31-11a3-236d1aa3a1c3,ad7ee026-e08a-4f73-ad11-7d3128af0633,e1955652-d0fd-44e5-a2db-0420ee2ec621,0bd4bd99-fb2b-426e-810b-64466bed6980,6215decf-751d-4da0-bdc7-c4071ec43621,bf3d5309-a356-49ca-8be9-320661a4dc7d,21ef22e0-f3dc-46a3-ba56-8ba25eea2f33,eb3b1264-f6ea-4152-ac0f-4f55d257e0a1,d7650732-21e0-4f56-8622-f8bcc8e99cd1,7559ae00-7fd1-4d40-abca-4e17cda7da7b,2790ef0f-873c-40d7-8b83-d7777ae3e45e,1972812c-10ff-4dcb-b198-760c6bba6ca3,d26f04df-0ceb-4ed7-a1dc-5d55d86cfd89,1a378687-11c8-4008-afa9-df55277796b4,ff45ea0e-dd6a-4076-b505-0896efa66e24,88550559-706e-4652-99aa-bb58967864f5,5a3dbc2f-974e-4f35-a3c6-a858dc01e9bd,05c69c05-da0a-475d-95a2-55a6b0507c63,37f3726d-a6e9-4747-b613-6bfe2a11dc7d,db362e99-1c0c-4e4b-82a9-1b91ebb68a4f,09704ffd-51c0-4cdf-8c5b-b2c78cfcbe2e,be9ad75f-b349-4d1a-b2b1-b852254cd7cd,2341f1b1-33b3-1d31-11a3-236d1aa3a1c3,3828801c-e28b-4d5c-b754-64db92d69cc3,313f732d-407f-45bb-a52d-40b56bb1ede7,ea2c3cfa-c429-479b-a3c9-20b8b4879f05,4c5b531f-eab3-4a55-8e59-285945f23629,44414d4d-a511-4b43-95a3-592d30027ca0,4c5b531f-eab3-4a55-8e59-285945f23629,44414d4d-a511-4b43-95a3-592d30027ca0,77c47e2b-118b-43be-80f2-17bb9c9b834d,39962154-ff5b-4114-bed7-63a3f16943ff,dfa62ecf-9578-4e3b-a254-7e76abe0cce8,4a0aca83-5990-4236-83d1-645d4c1e880e,4b479f5b-49f7-4c54-b33a-e3edfa7fa865,a70563e8-a3cc-421b-9d7b-ec64c28dcf7b,58d532bd-6f63-41b7-988a-7a3bcad58676,3dcc416b-73ef-4a28-bbbb-6af6de6710e1,bf5361e3-c415-49b4-bc24-1ffaf6f7e43f,9dc11d2a-ffcb-4d22-8486-cf64bd888ede,11f90723-ae72-4691-9090-4752b5d828dc,21fd1ce4-d68e-4286-ad6f-89371f4061d9,efa485fa-a610-478b-a637-49847d3e0daa,c53e1de2-9a8e-4db3-9f5d-2aa9debc407a,7731f1b1-33b3-1d31-11a3-236d1aa3a1c3,b5c67892-9f8e-4459-8c53-dcfb720c4ace,c1508e81-1a19-44eb-8c03-464a2f9a1418,1cdfaa66-3df1-448d-9c70-b004bd8f300c,88689fb5-365d-4341-9555-e3290216662f,0d87cbe4-5775-4c22-9de4-8967a4dc6a70,242b0ee0-2bde-43d6-ab20-6dd9ca138964,edb96bcc-e0bd-404e-b999-291917c6e18d,3331f1b1-32b3-1d22-11a3-322d1aa3a1c3,3431b2f9-d899-4323-ae95-395e0d104411,543daf0e-117d-42f5-8ee5-77fd9178bd89,7b4fe709-4fdb-41eb-885d-fee5ce257a9a,eb75759a-3c78-4efc-be16-443b50a7c582,3431b2f9-d858-4533-ae95-395e0d104410,c3390494-994f-47d1-a2da-f275a1ab4683,0309a247-c8a7-4011-8e18-29bdb093b757,e076a197-8ddf-4135-9ac7-641f5f326935,6f4ec66d-6ac9-4752-93fd-99c68f9b3544,313327e7-9b64-4f55-bd69-17bc0a0bd216,c659e296-aa1d-48e1-8b07-2f4f785bc9f1,3ff2f0a3-4840-4f77-aac0-978e6cd32ac7,c1505bc6-f16d-4a0b-93d9-fb19cddf06e2,368a7439-ae2b-4106-9a38-accea578debc,3bb76054-f185-4542-a18e-f645b37feee2,46ec26fb-f474-40d4-9d4d-836b4b24ac0d,fa3fe2cf-a45a-46d8-b26a-802686366ebc,86be9334-ac79-4d38-b85c-c592fa61dc58,21377d42-20cf-453d-9cd6-f8a21d14b76f,a759edf9-b33b-4c4f-9b59-cf6caee576b9,795b1800-eb56-456f-9f1c-d961a294aafa,6fb6b177-362f-46b2-a14a-e41261a2951a,2231f1b1-33b3-1d31-15a3-236d1aa3a1c3,d94ed947-ba1b-4841-ae6e-cc7a0f323a2a,c2ae0c92-f6d2-4c39-9b1b-a4fb4da220fb,15ba7873-6dd4-4c2f-9268-975ea15c28a6,917bab37-b92f-4d64-8bf8-6d2b50a80039,d94b62f7-6ab7-4ef6-b57c-ec774d71fa18,c752e9da-0fff-455b-8cd7-f95b23e66f35,0a6e2130-29e4-4cf8-a5c1-a2082237ccbf,9263a22f-4698-4baf-bab9-c24f2a0f932c,08a6c81b-f47a-4a9e-a1b0-7053bd6df02b,35e0d499-42c0-4e3e-9741-fdfa238baef9,7c8d87cb-cc97-42ac-ad21-119819501e5c,18f10e7d-2a6f-4b55-a244-001f4c464811,f1ec4f8b-9a2c-4818-8b0c-9852a722ea03,15f8134a-57ff-4aa8-8eee-c9b6c5a2dc52,c9261f75-9851-41fc-9112-84e6139b7dc4,8b3b4115-808f-43c5-9a1d-6dfac0a156a7,1cf64438-9d5e-4b2c-8cbc-ca023d78fd82,723beea3-0de5-4d61-bc20-24c6012f6e9e,f0f8b154-f32d-4ccc-b252-33283b5d6fa7,71076f7c-1d33-4f17-b58c-e84cfc48ff31,d3dfab27-7f58-4139-9e30-18e486adecdb,1331f1b1-33b3-1d31-11a3-236d1aa3a1c3,ad7ee026-e08a-4f73-ad11-7d3128af0633,e1955652-d0fd-44e5-a2db-0420ee2ec621,0bd4bd99-fb2b-426e-810b-64466bed6980,6215decf-751d-4da0-bdc7-c4071ec43621,bf3d5309-a356-49ca-8be9-320661a4dc7d,21ef22e0-f3dc-46a3-ba56-8ba25eea2f33,eb3b1264-f6ea-4152-ac0f-4f55d257e0a1,d7650732-21e0-4f56-8622-f8bcc8e99cd1,7559ae00-7fd1-4d40-abca-4e17cda7da7b,2790ef0f-873c-40d7-8b83-d7777ae3e45e,1972812c-10ff-4dcb-b198-760c6bba6ca3,d26f04df-0ceb-4ed7-a1dc-5d55d86cfd89,1a378687-11c8-4008-afa9-df55277796b4,ff45ea0e-dd6a-4076-b505-0896efa66e24,88550559-706e-4652-99aa-bb58967864f5,5a3dbc2f-974e-4f35-a3c6-a858dc01e9bd,05c69c05-da0a-475d-95a2-55a6b0507c63,37f3726d-a6e9-4747-b613-6bfe2a11dc7d,db362e99-1c0c-4e4b-82a9-1b91ebb68a4f,09704ffd-51c0-4cdf-8c5b-b2c78cfcbe2e,be9ad75f-b349-4d1a-b2b1-b852254cd7cd,2341f1b1-33b3-1d31-11a3-236d1aa3a1c3,3828801c-e28b-4d5c-b754-64db92d69cc3,313f732d-407f-45bb-a52d-40b56bb1ede7,3318ecbe-5719-4730-93e4-8eec664d2817,e0dd918a-fb39-499a-88ac-3a68ccd99c3b,958e4721-c438-493d-9909-693ff60a3ef0,ab6c11c3-45f9-4fcb-8872-12353bb7e547,7f9b36c9-7cf6-4b8a-be37-37e9ab9b63c2,35806e73-6177-4759-b0a3-6b77ecca700d,6599267e-d1da-438b-8dde-816636cdea7b,495d6492-a848-42fc-b7d5-b19514d726d7,adaad6f3-eba6-439a-a6d4-fdbebb406801,bc16d08a-7bfa-45f6-aedd-6c63263163a6,b9c16d78-1138-4a76-af84-51992b888a82,ded734d2-c935-4508-92c5-2202a7665e93,b7e744d9-e334-475e-bc0b-be29fd91075e,e7ed849a-04d8-4b8d-a8a0-2f225e2726bf,ed3cb8a1-aff3-4502-933c-c97ca24692ed,83af7bf6-1aff-4e43-a5c2-6b138a1621f4,3221f1b1-33b3-1d31-22a3-236d1aa3a1c3,15d4b11f-2fe6-47cc-93b2-d8fac392e3c0,cd70e1d0-6ce8-4af4-b257-17300d7e1f8e,543daf0e-117d-42f5-8ee5-77fd9178bd89,7b4fe709-4fdb-41eb-885d-fee5ce257a9a,eb75759a-3c78-4efc-be16-443b50a7c582,3431b2f9-d858-4533-ae95-395e0d104410,c3390494-994f-47d1-a2da-f275a1ab4683,0309a247-c8a7-4011-8e18-29bdb093b757,e076a197-8ddf-4135-9ac7-641f5f326935,6f4ec66d-6ac9-4752-93fd-99c68f9b3544,313327e7-9b64-4f55-bd69-17bc0a0bd216,c659e296-aa1d-48e1-8b07-2f4f785bc9f1,3ff2f0a3-4840-4f77-aac0-978e6cd32ac7,c1505bc6-f16d-4a0b-93d9-fb19cddf06e2,368a7439-ae2b-4106-9a38-accea578debc,3bb76054-f185-4542-a18e-f645b37feee2,46ec26fb-f474-40d4-9d4d-836b4b24ac0d,fa3fe2cf-a45a-46d8-b26a-802686366ebc,86be9334-ac79-4d38-b85c-c592fa61dc58,21377d42-20cf-453d-9cd6-f8a21d14b76f,a759edf9-b33b-4c4f-9b59-cf6caee576b9,795b1800-eb56-456f-9f1c-d961a294aafa,6fb6b177-362f-46b2-a14a-e41261a2951a,2231f1b1-33b3-1d31-15a3-236d1aa3a1c3,d94ed947-ba1b-4841-ae6e-cc7a0f323a2a,c2ae0c92-f6d2-4c39-9b1b-a4fb4da220fb,15ba7873-6dd4-4c2f-9268-975ea15c28a6,917bab37-b92f-4d64-8bf8-6d2b50a80039,d94b62f7-6ab7-4ef6-b57c-ec774d71fa18,25c485c2-dae0-448a-918a-e815b3bdfdc6,c367bb95-5cfa-4af2-9294-8493684a85a5,05541de1-9506-4feb-b2af-7914ceb3bd66,9afe6486-e794-4b9b-80a1-7c3e27270aea,51204faf-c7fd-4197-ae50-ca86ef6e886f,955a4509-2554-482c-9c7a-376d8c2ac0b1,502a0a45-9739-4ba8-9e84-268134d0999f,25524c4c-037b-4c3a-a771-6778b300f2b1,584da3d7-cdd6-458e-bd23-1e7de6cfe22d,74f6f885-c421-4106-8d16-fd32bf313637,7d239c06-cde7-40af-889d-fc3a8223de9d,bb002c44-cb90-4bf6-9cf2-6bebac5b6b50,8085b2ae-07e5-4768-b3b2-ebaa2afd6a7e,d0c27250-4cc5-488f-9d4a-7ba6f5c4e5fb,a6a3992a-2c3b-43d3-9e0e-9728597ddbc5,ed2d1469-3d06-45a1-bb49-de7b14cd26ea,80de8aa-0bee-4ee8-bbb2-eaff5af1b171,6ab2d9c8-66b8-4c3a-bab5-2e8544fc52d8,0062f5b2-56b5-48d9-ae17-b80c69f936fd,27e95a6d-25a8-40ca-96f5-c43b7f22ba34,85be1fd6-3711-42e7-927d-c002c461b9a7,95f6dd2b-134d-48aa-b177-57d84b970168,b306ba7f-e4f6-4810-b660-bb8272374849,670e4888-cad7-4176-8f03-a8945575972f,2afacccd-de6f-491d-a795-674b67448ab1,7ce8616b-4545-42c3-8938-bf852f7596a0,93d6c634-f7a1-4e33-a86e-2be136c9ffca,9ecc068f-115b-43a2-bdf5-eb31b5ea284a,5c6958ce-2713-4fbc-a7b0-70a47b33b3f7,3f2919e2-182b-429a-89e1-2f7ffbbbd465,06d44f7d-715e-47b1-b411-cb4d21dba39e,ef7a8c29-2b20-434c-aa05-8841923d2740,b3d73cfa-a82c-4b4d-a6cb-0e1563d4b19d,249d8fdc-0438-412a-84be-caa2d5b300f1,b5502311-ac0a-4862-bcfc-043cdd5a348f,daaad6f1-3b9c-4891-baa1-08eb4c200bf3,0b9533f1-fe92-4805-bf89-e036fd630c1e,797b2ae2-94ca-4761-bf4c-180e147702ea,b316bb0d-846d-4955-a596-809b51e3e93d,3331f1b1-33b3-1d31-11a3-236d1aa3a1c3,a9236169-d7af-40d9-84dd-0cdb96bde54a,dc003cc6-b80d-49c6-b501-ce3a14ed2a64,fcbd98d5-7caf-472e-9768-2ab2073dbe32,8381785a-78e6-4c52-8525-b716bc706e94,d6c2962d-0c98-4317-ac8f-4b06a1c0489d,c752e9da-0fff-455b-8cd7-f95b23e66f35,0a6e2130-29e4-4cf8-a5c1-a2082237ccbf,9263a22f-4698-4baf-bab9-c24f2a0f932c,08a6c81b-f47a-4a9e-a1b0-7053bd6df02b,35e0d499-42c0-4e3e-9741-fdfa238baef9,7c8d87cb-cc97-42ac-ad21-119819501e5c,18f10e7d-2a6f-4b55-a244-001f4c464811,f1ec4f8b-9a2c-4818-8b0c-9852a722ea03,15f8134a-57ff-4aa8-8eee-c9b6c5a2dc52,c9261f75-9851-41fc-9112-84e6139b7dc4,8b3b4115-808f-43c5-9a1d-6dfac0a156a7,1cf64438-9d5e-4b2c-8cbc-ca023d78fd82,723beea3-0de5-4d61-bc20-24c6012f6e9e,f0f8b154-f32d-4ccc-b252-33283b5d6fa7,71076f7c-1d33-4f17-b58c-e84cfc48ff31,d3dfab27-7f58-4139-9e30-18e486adecdb,1331f1b1-33b3-1d31-11a3-236d1aa3a1c3,ad7ee026-e08a-4f73-ad11-7d3128af0633,e1955652-d0fd-44e5-a2db-0420ee2ec621,0bd4bd99-fb2b-426e-810b-64466bed6980,6215decf-751d-4da0-bdc7-c4071ec43621,bf3d5309-a356-49ca-8be9-320661a4dc7d,4c5b531f-eab3-4a55-8e59-285945f23629,44414d4d-a511-4b43-95a3-592d30027ca0,77c47e2b-118b-43be-80f2-17bb9c9b834d,39962154-ff5b-4114-bed7-63a3f16943ff,dfa62ecf-9578-4e3b-a254-7e76abe0cce8,4a0aca83-5990-4236-83d1-645d4c1e880e,4b479f5b-49f7-4c54-b33a-e3edfa7fa865,a70563e8-a3cc-421b-9d7b-ec64c28dcf7b,58d532bd-6f63-41b7-988a-7a3bcad58676,3dcc416b-73ef-4a28-bbbb-6af6de6710e1,bf5361e3-c415-49b4-bc24-1ffaf6f7e43f,9dc11d2a-ffcb-4d22-8486-cf64bd888ede,11f90723-ae72-4691-9090-4752b5d828dc,21fd1ce4-d68e-4286-ad6f-89371f4061d9,efa485fa-a610-478b-a637-49847d3e0daa,c53e1de2-9a8e-4db3-9f5d-2aa9debc407a,7731f1b1-33b3-1d31-11a3-236d1aa3a1c3,b5c67892-9f8e-4459-8c53-dcfb720c4ace,c1508e81-1a19-44eb-8c03-464a2f9a1418,1cdfaa66-3df1-448d-9c70-b004bd8f300c,88689fb5-365d-4341-9555-e3290216662f,0d87cbe4-5775-4c22-9de4-8967a4dc6a70,242b0ee0-2bde-43d6-ab20-6dd9ca138964,edb96bcc-e0bd-404e-b999-291917c6e18d,3331f1b1-32b3-1d22-11a3-322d1aa3a1c3,3431b2f9-d899-4323-ae95-395e0d104411,3318ecbe-5719-4730-93e4-8eec664d2817,e0dd918a-fb39-499a-88ac-3a68ccd99c3b,958e4721-c438-493d-9909-693ff60a3ef0,ab6c11c3-45f9-4fcb-8872-12353bb7e547,7f9b36c9-7cf6-4b8a-be37-37e9ab9b63c2,35806e73-6177-4759-b0a3-6b77ecca700d,6599267e-d1da-438b-8dde-816636cdea7b,495d6492-a848-42fc-b7d5-b19514d726d7,adaad6f3-eba6-439a-a6d4-fdbebb406801,bc16d08a-7bfa-45f6-aedd-6c63263163a6,b9c16d78-1138-4a76-af84-51992b888a82,ded734d2-c935-4508-92c5-2202a7665e93,b7e744d9-e334-475e-bc0b-be29fd91075e,e7ed849a-04d8-4b8d-a8a0-2f225e2726bf,ed3cb8a1-aff3-4502-933c-c97ca24692ed,83af7bf6-1aff-4e43-a5c2-6b138a1621f4,3221f1b1-33b3-1d31-22a3-236d1aa3a1c3,15d4b11f-2fe6-47cc-93b2-d8fac392e3c0,cd70e1d0-6ce8-4af4-b257-17300d7e1f8e,543daf0e-117d-42f5-8ee5-77fd9178bd89,7b4fe709-4fdb-41eb-885d-fee5ce257a9a,eb75759a-3c78-4efc-be16-443b50a7c582,3431b2f9-d858-4533-ae95-395e0d104410,c3390494-994f-47d1-a2da-f275a1ab4683,15ba7873-6dd4-4c2f-9268-975ea15c28a6,917bab37-b92f-4d64-8bf8-6d2b50a80039,d94b62f7-6ab7-4ef6-b57c-ec774d71fa18,25c485c2-dae0-448a-918a-e815b3bdfdc6,c367bb95-5cfa-4af2-9294-8493684a85a5,05541de1-9506-4feb-b2af-7914ceb3bd66,9afe6486-e794-4b9b-80a1-7c3e27270aea,51204faf-c7fd-4197-ae50-ca86ef6e886f,955a4509-2554-482c-9c7a-376d8c2ac0b1,502a0a45-9739-4ba8-9e84-268134d0999f,25524c4c-037b-4c3a-a771-6778b300f2b1,584da3d7-cdd6-458e-bd23-1e7de6cfe22d,74f6f885-c421-4106-8d16-fd32bf313637,7d239c06-cde7-40af-889d-fc3a8223de9d,bb002c44-cb90-4bf6-9cf2-6bebac5b6b50,8085b2ae-07e5-4768-b3b2-ebaa2afd6a7e,d0c27250-4cc5-488f-9d4a-7ba6f5c4e5fb,a6a3992a-2c3b-43d3-9e0e-9728597ddbc5,ed2d1469-3d06-45a1-bb49-de7b14cd26ea,80de8aa-0bee-4ee8-bbb2-eaff5af1b171,6ab2d9c8-66b8-4c3a-bab5-2e8544fc52d8,0062f5b2-56b5-48d9-ae17-b80c69f936fd,27e95a6d-25a8-40ca-96f5-c43b7f22ba34,85be1fd6-3711-42e7-927d-c002c461b9a7,95f6dd2b-134d-48aa-b177-57d84b970168,b306ba7f-e4f6-4810-b660-bb8272374849,0bd4bd99-fb2b-426e-810b-64466bed6980,6215decf-751d-4da0-bdc7-c4071ec43621,bf3d5309-a356-49ca-8be9-320661a4dc7d,ea2c3cfa-c429-479b-a3c9-20b8b4879f05,4c5b531f-eab3-4a55-8e59-285945f23629,44414d4d-a511-4b43-95a3-592d30027ca0,4c5b531f-eab3-4a55-8e59-285945f23629,44414d4d-a511-4b43-95a3-592d30027ca0,77c47e2b-118b-43be-80f2-17bb9c9b834d,39962154-ff5b-4114-bed7-63a3f16943ff,dfa62ecf-9578-4e3b-a254-7e76abe0cce8,4a0aca83-5990-4236-83d1-645d4c1e880e,4b479f5b-49f7-4c54-b33a-e3edfa7fa865,a70563e8-a3cc-421b-9d7b-ec64c28dcf7b,58d532bd-6f63-41b7-988a-7a3bcad58676,3dcc416b-73ef-4a28-bbbb-6af6de6710e1,bf5361e3-c415-49b4-bc24-1ffaf6f7e43f,9dc11d2a-ffcb-4d22-8486-cf64bd888ede,11f90723-ae72-4691-9090-4752b5d828dc,21fd1ce4-d68e-4286-ad6f-89371f4061d9,efa485fa-a610-478b-a637-49847d3e0daa,c53e1de2-9a8e-4db3-9f5d-2aa9debc407a,7731f1b1-33b3-1d31-11a3-236d1aa3a1c3,b5c67892-9f8e-4459-8c53-dcfb720c4ace,c1508e81-1a19-44eb-8c03-464a2f9a1418,1cdfaa66-3df1-448d-9c70-b004bd8f300c,88689fb5-365d-4341-9555-e3290216662f,0d87cbe4-5775-4c22-9de4-8967a4dc6a70,242b0ee0-2bde-43d6-ab20-6dd9ca138964,edb96bcc-e0bd-404e-b999-291917c6e18d,3331f1b1-32b3-1d22-11a3-322d1aa3a1c3,3431b2f9-d899-4323-ae95-395e0d104411,3318ecbe-5719-4730-93e4-8eec664d2817,e0dd918a-fb39-499a-88ac-3a68ccd99c3b,958e4721-c438-493d-9909-693ff60a3ef0,ab6c11c3-45f9-4fcb-8872-12353bb7e547,7f9b36c9-7cf6-4b8a-be37-37e9ab9b63c2,35806e73-6177-4759-b0a3-6b77ecca700d,6599267e-d1da-438b-8dde-816636cdea7b,495d6492-a848-42fc-b7d5-b19514d726d7,adaad6f3-eba6-439a-a6d4-fdbebb406801,bc16d08a-7bfa-45f6-aedd-6c63263163a6,b9c16d78-1138-4a76-af84-51992b888a82,ded734d2-c935-4508-92c5-2202a7665e93,b7e744d9-e334-475e-bc0b-be29fd91075e,e7ed849a-04d8-4b8d-a8a0-2f225e2726bf,ed3cb8a1-aff3-4502-933c-c97ca24692ed,83af7bf6-1aff-4e43-a5c2-6b138a1621f4,3221f1b1-33b3-1d31-22a3-236d1aa3a1c3,15d4b11f-2fe6-47cc-93b2-d8fac392e3c0,cd70e1d0-6ce8-4af4-b257-17300d7e1f8e,543daf0e-117d-42f5-8ee5-77fd9178bd89,7b4fe709-4fdb-41eb-885d-fee5ce257a9a,eb75759a-3c78-4efc-be16-443b50a7c582,3431b2f9-d858-4533-ae95-395e0d104410,c3390494-994f-47d1-a2da-f275a1ab4683,0309a247-c8a7-4011-8e18-29bdb093b757,e076a197-8ddf-4135-9ac7-641f5f326935,6f4ec66d-6ac9-4752-93fd-99c68f9b3544,313327e7-9b64-4f55-bd69-17bc0a0bd216,c659e296-aa1d-48e1-8b07-2f4f785bc9f1,3ff2f0a3-4840-4f77-aac0-978e6cd32ac7,c1505bc6-f16d-4a0b-93d9-fb19cddf06e2,368a7439-ae2b-4106-9a38-accea578debc,3bb76054-f185-4542-a18e-f645b37feee2,46ec26fb-f474-40d4-9d4d-836b4b24ac0d,fa3fe2cf-a45a-46d8-b26a-802686366ebc,86be9334-ac79-4d38-b85c-c592fa61dc58,21377d42-20cf-453d-9cd6-f8a21d14b76f,a759edf9-b33b-4c4f-9b59-cf6caee576b9,795b1800-eb56-456f-9f1c-d961a294aafa,6fb6b177-362f-46b2-a14a-e41261a2951a,2231f1b1-33b3-1d31-15a3-236d1aa3a1c3,d94ed947-ba1b-4841-ae6e-cc7a0f323a2a,c2ae0c92-f6d2-4c39-9b1b-a4fb4da220fb,25c485c2-dae0-448a-918a-e815b3bdfdc6,c367bb95-5cfa-4af2-9294-8493684a85a5,05541de1-9506-4feb-b2af-7914ceb3bd66,9afe6486-e794-4b9b-80a1-7c3e27270aea,51204faf-c7fd-4197-ae50-ca86ef6e886f,955a4509-2554-482c-9c7a-376d8c2ac0b1,502a0a45-9739-4ba8-9e84-268134d0999f,25524c4c-037b-4c3a-a771-6778b300f2b1,584da3d7-cdd6-458e-bd23-1e7de6cfe22d,74f6f885-c421-4106-8d16-fd32bf313637,7d239c06-cde7-40af-889d-fc3a8223de9d,bb002c44-cb90-4bf6-9cf2-6bebac5b6b50,8085b2ae-07e5-4768-b3b2-ebaa2afd6a7e,d0c27250-4cc5-488f-9d4a-7ba6f5c4e5fb,a6a3992a-2c3b-43d3-9e0e-9728597ddbc5,ed2d1469-3d06-45a1-bb49-de7b14cd26ea,80de8aa-0bee-4ee8-bbb2-eaff5af1b171,6ab2d9c8-66b8-4c3a-bab5-2e8544fc52d8,0062f5b2-56b5-48d9-ae17-b80c69f936fd,27e95a6d-25a8-40ca-96f5-c43b7f22ba34,85be1fd6-3711-42e7-927d-c002c461b9a7,95f6dd2b-134d-48aa-b177-57d84b970168,b306ba7f-e4f6-4810-b660-bb8272374849,ea2c3cfa-c429-479b-a3c9-20b8b4879f05,4c5b531f-eab3-4a55-8e59-285945f23629,44414d4d-a511-4b43-95a3-592d30027ca0,4c5b531f-eab3-4a55-8e59-285945f23629,44414d4d-a511-4b43-95a3-592d30027ca0,77c47e2b-118b-43be-80f2-17bb9c9b834d,39962154-ff5b-4114-bed7-63a3f16943ff,dfa62ecf-9578-4e3b-a254-7e76abe0cce8,4a0aca83-5990-4236-83d1-645d4c1e880e,4b479f5b-49f7-4c54-b33a-e3edfa7fa865,a70563e8-a3cc-421b-9d7b-ec64c28dcf7b,58d532bd-6f63-41b7-988a-7a3bcad58676,3dcc416b-73ef-4a28-bbbb-6af6de6710e1,bf5361e3-c415-49b4-bc24-1ffaf6f7e43f,9dc11d2a-ffcb-4d22-8486-cf64bd888ede,11f90723-ae72-4691-9090-4752b5d828dc,21fd1ce4-d68e-4286-ad6f-89371f4061d9,efa485fa-a610-478b-a637-49847d3e0daa,c53e1de2-9a8e-4db3-9f5d-2aa9debc407a,7731f1b1-33b3-1d31-11a3-236d1aa3a1c3,b5c67892-9f8e-4459-8c53-dcfb720c4ace,c1508e81-1a19-44eb-8c03-464a2f9a1418,1cdfaa66-3df1-448d-9c70-b004bd8f300c,88689fb5-365d-4341-9555-e3290216662f,0d87cbe4-5775-4c22-9de4-8967a4dc6a70,242b0ee0-2bde-43d6-ab20-6dd9ca138964,edb96bcc-e0bd-404e-b999-291917c6e18d,3331f1b1-32b3-1d22-11a3-322d1aa3a1c3,3431b2f9-d899-4323-ae95-395e0d104411,3318ecbe-5719-4730-93e4-8eec664d2817,e0dd918a-fb39-499a-88ac-3a68ccd99c3b,958e4721-c438-493d-9909-693ff60a3ef0,ab6c11c3-45f9-4fcb-8872-12353bb7e547,7f9b36c9-7cf6-4b8a-be37-37e9ab9b63c2,35806e73-6177-4759-b0a3-6b77ecca700d,6599267e-d1da-438b-8dde-816636cdea7b,495d6492-a848-42fc-b7d5-b19514d726d7,adaad6f3-eba6-439a-a6d4-fdbebb406801,bc16d08a-7bfa-45f6-aedd-6c63263163a6,b9c16d78-1138-4a76-af84-51992b888a82,ded734d2-c935-4508-92c5-2202a7665e93,b7e744d9-e334-475e-bc0b-be29fd91075e,e7ed849a-04d8-4b8d-a8a0-2f225e2726bf,ed3cb8a1-aff3-4502-933c-c97ca24692ed,83af7bf6-1aff-4e43-a5c2-6b138a1621f4,3221f1b1-33b3-1d31-22a3-236d1aa3a1c3,15d4b11f-2fe6-47cc-93b2-d8fac392e3c0,cd70e1d0-6ce8-4af4-b257-17300d7e1f8e,543daf0e-117d-42f5-8ee5-77fd9178bd89,7b4fe709-4fdb-41eb-885d-fee5ce257a9a,eb75759a-3c78-4efc-be16-443b50a7c582,3431b2f9-d858-4533-ae95-395e0d104410,c3390494-994f-47d1-a2da-f275a1ab4683,0309a247-c8a7-4011-8e18-29bdb093b757,e076a197-8ddf-4135-9ac7-641f5f326935,6f4ec66d-6ac9-4752-93fd-99c68f9b3544,313327e7-9b64-4f55-bd69-17bc0a0bd216,c659e296-aa1d-48e1-8b07-2f4f785bc9f1,3ff2f0a3-4840-4f77-aac0-978e6cd32ac7,c1505bc6-f16d-4a0b-93d9-fb19cddf06e2,368a7439-ae2b-4106-9a38-accea578debc,3bb76054-f185-4542-a18e-f645b37feee2,46ec26fb-f474-40d4-9d4d-836b4b24ac0d,fa3fe2cf-a45a-46d8-b26a-802686366ebc,86be9334-ac79-4d38-b85c-c592fa61dc58,21377d42-20cf-453d-9cd6-f8a21d14b76f,a759edf9-b33b-4c4f-9b59-cf6caee576b9,795b1800-eb56-456f-9f1c-d961a294aafa,6fb6b177-362f-46b2-a14a-e41261a2951a,2231f1b1-33b3-1d31-15a3-236d1aa3a1c3,d94ed947-ba1b-4841-ae6e-cc7a0f323a2a,c2ae0c92-f6d2-4c39-9b1b-a4fb4da220fb,15ba7873-6dd4-4c2f-9268-975ea15c28a6,917bab37-b92f-4d64-8bf8-6d2b50a80039,d94b62f7-6ab7-4ef6-b57c-ec774d71fa18,25c485c2-dae0-448a-918a-e815b3bdfdc6,c367bb95-5cfa-4af2-9294-8493684a85a5,05541de1-9506-4feb-b2af-7914ceb3bd66,9afe6486-e794-4b9b-80a1-7c3e27270aea,51204faf-c7fd-4197-ae50-ca86ef6e886f,955a4509-2554-482c-9c7a-376d8c2ac0b1,502a0a45-9739-4ba8-9e84-268134d0999f,25524c4c-037b-4c3a-a771-6778b300f2b1,584da3d7-cdd6-458e-bd23-1e7de6cfe22d,74f6f885-c421-4106-8d16-fd32bf313637,7d239c06-cde7-40af-889d-fc3a8223de9d,bb002c44-cb90-4bf6-9cf2-6bebac5b6b50,8085b2ae-07e5-4768-b3b2-ebaa2afd6a7e,d0c27250-4cc5-488f-9d4a-7ba6f5c4e5fb,a6a3992a-2c3b-43d3-9e0e-9728597ddbc5,ed2d1469-3d06-45a1-bb49-de7b14cd26ea,80de8aa-0bee-4ee8-bbb2-eaff5af1b171,6ab2d9c8-66b8-4c3a-bab5-2e8544fc52d8,0062f5b2-56b5-48d9-ae17-b80c69f936fd,27e95a6d-25a8-40ca-96f5-c43b7f22ba34,85be1fd6-3711-42e7-927d-c002c461b9a7,95f6dd2b-134d-48aa-b177-57d84b970168,b306ba7f-e4f6-4810-b660-bb8272374849,670e4888-cad7-4176-8f03-a8945575972f,2afacccd-de6f-491d-a795-674b67448ab1,7ce8616b-4545-42c3-8938-bf852f7596a0,93d6c634-f7a1-4e33-a86e-2be136c9ffca,9ecc068f-115b-43a2-bdf5-eb31b5ea284a,5c6958ce-2713-4fbc-a7b0-70a47b33b3f7,3f2919e2-182b-429a-89e1-2f7ffbbbd465,06d44f7d-715e-47b1-b411-cb4d21dba39e,ef7a8c29-2b20-434c-aa05-8841923d2740,b3d73cfa-a82c-4b4d-a6cb-0e1563d4b19d,249d8fdc-0438-412a-84be-caa2d5b300f1,b5502311-ac0a-4862-bcfc-043cdd5a348f,daaad6f1-3b9c-4891-baa1-08eb4c200bf3,0b9533f1-fe92-4805-bf89-e036fd630c1e,797b2ae2-94ca-4761-bf4c-180e147702ea,b316bb0d-846d-4955-a596-809b51e3e93d,3331f1b1-33b3-1d31-11a3-236d1aa3a1c3,a9236169-d7af-40d9-84dd-0cdb96bde54a,dc003cc6-b80d-49c6-b501-ce3a14ed2a64,fcbd98d5-7caf-472e-9768-2ab2073dbe32,8381785a-78e6-4c52-8525-b716bc706e94,d6c2962d-0c98-4317-ac8f-4b06a1c0489d,c752e9da-0fff-455b-8cd7-f95b23e66f35,0a6e2130-29e4-4cf8-a5c1-a2082237ccbf,9263a22f-4698-4baf-bab9-c24f2a0f932c,08a6c81b-f47a-4a9e-a1b0-7053bd6df02b,35e0d499-42c0-4e3e-9741-fdfa238baef9,7c8d87cb-cc97-42ac-ad21-119819501e5c,18f10e7d-2a6f-4b55-a244-001f4c464811,f1ec4f8b-9a2c-4818-8b0c-9852a722ea03,15f8134a-57ff-4aa8-8eee-c9b6c5a2dc52,c9261f75-9851-41fc-9112-84e6139b7dc4,8b3b4115-808f-43c5-9a1d-6dfac0a156a7,1cf64438-9d5e-4b2c-8cbc-ca023d78fd82,723beea3-0de5-4d61-bc20-24c6012f6e9e,f0f8b154-f32d-4ccc-b252-33283b5d6fa7,71076f7c-1d33-4f17-b58c-e84cfc48ff31,d3dfab27-7f58-4139-9e30-18e486adecdb,1331f1b1-33b3-1d31-11a3-236d1aa3a1c3,ad7ee026-e08a-4f73-ad11-7d3128af0633,e1955652-d0fd-44e5-a2db-0420ee2ec621,0bd4bd99-fb2b-426e-810b-64466bed6980,6215decf-751d-4da0-bdc7-c4071ec43621,bf3d5309-a356-49ca-8be9-320661a4dc7d,ea2c3cfa-c429-479b-a3c9-20b8b4879f05,4c5b531f-eab3-4a55-8e59-285945f23629,44414d4d-a511-4b43-95a3-592d30027ca0,4c5b531f-eab3-4a55-8e59-285945f23629,44414d4d-a511-4b43-95a3-592d30027ca0,77c47e2b-118b-43be-80f2-17bb9c9b834d,39962154-ff5b-4114-bed7-63a3f16943ff,dfa62ecf-9578-4e3b-a254-7e76abe0cce8,4a0aca83-5990-4236-83d1-645d4c1e880e,4b479f5b-49f7-4c54-b33a-e3edfa7fa865,a70563e8-a3cc-421b-9d7b-ec64c28dcf7b,58d532bd-6f63-41b7-988a-7a3bcad58676,3dcc416b-73ef-4a28-bbbb-6af6de6710e1,bf5361e3-c415-49b4-bc24-1ffaf6f7e43f,9dc11d2a-ffcb-4d22-8486-cf64bd888ede,11f90723-ae72-4691-9090-4752b5d828dc,21fd1ce4-d68e-4286-ad6f-89371f4061d9,efa485fa-a610-478b-a637-49847d3e0daa,c53e1de2-9a8e-4db3-9f5d-2aa9debc407a,7731f1b1-33b3-1d31-11a3-236d1aa3a1c3,b5c67892-9f8e-4459-8c53-dcfb720c4ace,c1508e81-1a19-44eb-8c03-464a2f9a1418,1cdfaa66-3df1-448d-9c70-b004bd8f300c,88689fb5-365d-4341-9555-e3290216662f,0d87cbe4-5775-4c22-9de4-8967a4dc6a70,242b0ee0-2bde-43d6-ab20-6dd9ca138964,edb96bcc-e0bd-404e-b999-291917c6e18d,3331f1b1-32b3-1d22-11a3-322d1aa3a1c3,3431b2f9-d899-4323-ae95-395e0d104411,3318ecbe-5719-4730-93e4-8eec664d2817,e0dd918a-fb39-499a-88ac-3a68ccd99c3b,958e4721-c438-493d-9909-693ff60a3ef0,ab6c11c3-45f9-4fcb-8872-12353bb7e547,7f9b36c9-7cf6-4b8a-be37-37e9ab9b63c2,35806e73-6177-4759-b0a3-6b77ecca700d,6599267e-d1da-438b-8dde-816636cdea7b,495d6492-a848-42fc-b7d5-b19514d726d7,adaad6f3-eba6-439a-a6d4-fdbebb406801,bc16d08a-7bfa-45f6-aedd-6c63263163a6,b9c16d78-1138-4a76-af84-51992b888a82,ded734d2-c935-4508-92c5-2202a7665e93,b7e744d9-e334-475e-bc0b-be29fd91075e,e7ed849a-04d8-4b8d-a8a0-2f225e2726bf,ed3cb8a1-aff3-4502-933c-c97ca24692ed,83af7bf6-1aff-4e43-a5c2-6b138a1621f4,3221f1b1-33b3-1d31-22a3-236d1aa3a1c3,15d4b11f-2fe6-47cc-93b2-d8fac392e3c0,cd70e1d0-6ce8-4af4-b257-17300d7e1f8e,543daf0e-117d-42f5-8ee5-77fd9178bd89,7b4fe709-4fdb-41eb-885d-fee5ce257a9a,eb75759a-3c78-4efc-be16-443b50a7c582,3431b2f9-d858-4533-ae95-395e0d104410,c3390494-994f-47d1-a2da-f275a1ab4683,15ba7873-6dd4-4c2f-9268-975ea15c28a6,917bab37-b92f-4d64-8bf8-6d2b50a80039,d94b62f7-6ab7-4ef6-b57c-ec774d71fa18,670e4888-cad7-4176-8f03-a8945575972f,2afacccd-de6f-491d-a795-674b67448ab1,7ce8616b-4545-42c3-8938-bf852f7596a0,93d6c634-f7a1-4e33-a86e-2be136c9ffca,9ecc068f-115b-43a2-bdf5-eb31b5ea284a,5c6958ce-2713-4fbc-a7b0-70a47b33b3f7,3f2919e2-182b-429a-89e1-2f7ffbbbd465,06d44f7d-715e-47b1-b411-cb4d21dba39e,ef7a8c29-2b20-434c-aa05-8841923d2740,b3d73cfa-a82c-4b4d-a6cb-0e1563d4b19d,249d8fdc-0438-412a-84be-caa2d5b300f1,b5502311-ac0a-4862-bcfc-043cdd5a348f,daaad6f1-3b9c-4891-baa1-08eb4c200bf3,0b9533f1-fe92-4805-bf89-e036fd630c1e,797b2ae2-94ca-4761-bf4c-180e147702ea,b316bb0d-846d-4955-a596-809b51e3e93d,3331f1b1-33b3-1d31-11a3-236d1aa3a1c3,a9236169-d7af-40d9-84dd-0cdb96bde54a,dc003cc6-b80d-49c6-b501-ce3a14ed2a64,fcbd98d5-7caf-472e-9768-2ab2073dbe32,8381785a-78e6-4c52-8525-b716bc706e94,d6c2962d-0c98-4317-ac8f-4b06a1c0489d,c752e9da-0fff-455b-8cd7-f95b23e66f35,0a6e2130-29e4-4cf8-a5c1-a2082237ccbf,9263a22f-4698-4baf-bab9-c24f2a0f932c,08a6c81b-f47a-4a9e-a1b0-7053bd6df02b,35e0d499-42c0-4e3e-9741-fdfa238baef9,7c8d87cb-cc97-42ac-ad21-119819501e5c,18f10e7d-2a6f-4b55-a244-001f4c464811,f1ec4f8b-9a2c-4818-8b0c-9852a722ea03,15f8134a-57ff-4aa8-8eee-c9b6c5a2dc52,c9261f75-9851-41fc-9112-84e6139b7dc4,8b3b4115-808f-43c5-9a1d-6dfac0a156a7,1cf64438-9d5e-4b2c-8cbc-ca023d78fd82,723beea3-0de5-4d61-bc20-24c6012f6e9e,f0f8b154-f32d-4ccc-b252-33283b5d6fa7,71076f7c-1d33-4f17-b58c-e84cfc48ff31,d3dfab27-7f58-4139-9e30-18e486adecdb,1331f1b1-33b3-1d31-11a3-236d1aa3a1c3,ad7ee026-e08a-4f73-ad11-7d3128af0633,e1955652-d0fd-44e5-a2db-0420ee2ec621,0bd4bd99-fb2b-426e-810b-64466bed6980,6215decf-751d-4da0-bdc7-c4071ec43621,bf3d5309-a356-49ca-8be9-320661a4dc7d,21ef22e0-f3dc-46a3-ba56-8ba25eea2f33,eb3b1264-f6ea-4152-ac0f-4f55d257e0a1,d7650732-21e0-4f56-8622-f8bcc8e99cd1,7559ae00-7fd1-4d40-abca-4e17cda7da7b,2790ef0f-873c-40d7-8b83-d7777ae3e45e,1972812c-10ff-4dcb-b198-760c6bba6ca3,d26f04df-0ceb-4ed7-a1dc-5d55d86cfd89,1a378687-11c8-4008-afa9-df55277796b4,ff45ea0e-dd6a-4076-b505-0896efa66e24,88550559-706e-4652-99aa-bb58967864f5,5a3dbc2f-974e-4f35-a3c6-a858dc01e9bd,05c69c05-da0a-475d-95a2-55a6b0507c63,37f3726d-a6e9-4747-b613-6bfe2a11dc7d,db362e99-1c0c-4e4b-82a9-1b91ebb68a4f,09704ffd-51c0-4cdf-8c5b-b2c78cfcbe2e,be9ad75f-b349-4d1a-b2b1-b852254cd7cd,2341f1b1-33b3-1d31-11a3-236d1aa3a1c3,3828801c-e28b-4d5c-b754-64db92d69cc3,313f732d-407f-45bb-a52d-40b56bb1ede7"
	numberOfMetadataFieldCharacters := len(longMetadataValueThatFailedBefore)
	fileRecordToWrite := storageClientV2.Record{
		Metadata: storageClientV2.Meta{
			WriterID: clientUUID,
			UserID:   clientUUID,
			Type:     recordType,
			Plain: map[string]string{
				"survey_question_ids": longMetadataValueThatFailedBefore,
			},
			FileMeta: &storageClientV2.FileMeta{
				Size:     fileLength,
				Checksum: hashString,
			},
		},
	}
	pendingFileURL, err := storageClient.WriteFile(testCtx, fileRecordToWrite)
	if err != nil {
		t.Fatalf("Call to file post should return 200 level status code returned %+v", err)
	}
	// Write the file to the server directed location
	req, err := http.NewRequest("PUT", pendingFileURL.FileURL, strings.NewReader(fileValue))
	req.Header.Set("Content-MD5", hashString)
	req.Header.Set("Content-Type", "application/octet-stream")
	if err != nil {
		t.Fatalf("Creation of put request should not cause an error")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
		t.Fatalf("Put to pendingFileURL with presigned URL should not error %+v resp %+v", err, resp)
	}
	// Register the file as being written
	_, err = pdsServiceClient.FileCommit(testCtx, pendingFileURL.PendingFileID.String())
	if err != nil {
		t.Fatalf("Pending file commit should not fail for file that has been loaded to datastore %+v and with field value of length %d", err, numberOfMetadataFieldCharacters)
	}
}

// Tests creating a group with valid authorization and valid group name.
func TestCreateGroupSucceedsWithValidInput(t *testing.T) {
	// Make request through cyclops to test tozny header is parsed properly
	registrationClient := accountClient.New(e3dbClients.ClientConfig{Host: cyclopsServiceHost}) // empty account host to make registration request
	queenClientConfig, _, err := test.MakeE3DBAccount(t, &registrationClient, uuid.New().String(), cyclopsServiceHost)
	if err != nil {
		t.Fatalf("Could not register account %s\n", err)
	}
	StorageClient := storageClientV2.New(queenClientConfig)
	encryptionKeyPair, err := e3dbClients.GenerateKeyPair()
	if err != nil {
		t.Errorf("Failed generating encryption key pair %s", err)
		return
	}
	eak, err := e3dbClients.EncryptPrivateKey(encryptionKeyPair.Private, StorageClient.EncryptionKeys)
	if err != nil {
		t.Errorf("Failed generating encrypted group key  %s", err)
	}
	group := storageClientV2.CreateGroupRequest{
		Name:              "TestGroup1" + uuid.New().String(),
		PublicKey:         encryptionKeyPair.Public.Material,
		EncryptedGroupKey: eak,
	}
	response, err := StorageClient.CreateGroup(testCtx, group)
	if err != nil {
		t.Fatalf("Failed to create group \n Group( %+v) \n error %+v", group, err)
	}
	if response.Name != group.Name {
		t.Fatalf("Group name (%+v) passed in, does not match Group name (%+v) inserted for Group( %+v) \n", group.Name, response.Name, group)
	}
}

// Creates a group and then fetches it.
func TestReadGroupWithValidInputSucceeds(t *testing.T) {
	// Make request through cyclops to test tozny header is parsed properly
	registrationClient := accountClient.New(e3dbClients.ClientConfig{Host: cyclopsServiceHost}) // empty account host to make registration request
	queenClientConfig, _, err := test.MakeE3DBAccount(t, &registrationClient, uuid.New().String(), cyclopsServiceHost)
	if err != nil {
		t.Fatalf("Could not register account %s\n", err)
	}
	StorageClient := storageClientV2.New(queenClientConfig)
	//Insert A Group To Look up
	encryptionKeyPair, err := e3dbClients.GenerateKeyPair()
	if err != nil {
		t.Errorf("Failed generating encryption key pair %s", err)
		return
	}
	eak, err := e3dbClients.EncryptPrivateKey(encryptionKeyPair.Private, StorageClient.EncryptionKeys)
	if err != nil {
		t.Errorf("Failed generating encrypted group key  %s", err)
	}
	group := storageClientV2.CreateGroupRequest{
		Name:              "TestGroup1" + uuid.New().String(),
		PublicKey:         encryptionKeyPair.Public.Material,
		EncryptedGroupKey: eak,
	}
	response, err := StorageClient.CreateGroup(testCtx, group)
	if err != nil {
		t.Fatalf("Failed to create group \n Group( %+v) \n error %+v", group, err)
	}
	if response.Name != group.Name {
		t.Fatalf("Group name (%+v) passed in, does not match Group name (%+v) inserted for Group( %+v) \n", group.Name, response.Name, group)
	}
	//Look Up Group Created
	groupID := storageClientV2.DescribeGroupRequest{
		GroupID: response.GroupID,
	}
	response, err = StorageClient.DescribeGroup(testCtx, groupID)
	if err != nil {
		t.Logf("Group: %+v Failed to be Found\n error %+v \n response %+v", group, err, response)
	}
	if groupID.GroupID != response.GroupID {
		t.Fatalf("GroupID (%+v) passed in, does not match GroupID(%+v) returned for Group( %+v) \n", groupID.GroupID, response.GroupID, response)
	}
}
func TestDeleteGroupWithValidCapabilitySucceeds(t *testing.T) {

	// Make request through cyclops to test tozny header is parsed properly
	registrationClient := accountClient.New(e3dbClients.ClientConfig{Host: cyclopsServiceHost}) // empty account host to make registration request
	queenClientConfig, _, err := test.MakeE3DBAccount(t, &registrationClient, uuid.New().String(), cyclopsServiceHost)
	if err != nil {
		t.Fatalf("Could not register account %s\n", err)
	}
	StorageClient := storageClientV2.New(queenClientConfig)

	//Insert A Group To Delete
	encryptionKeyPair, err := e3dbClients.GenerateKeyPair()
	if err != nil {
		t.Errorf("Failed generating encryption key pair %s", err)
		return
	}
	eak, err := e3dbClients.EncryptPrivateKey(encryptionKeyPair.Private, StorageClient.EncryptionKeys)
	if err != nil {
		t.Errorf("Failed generating encrypted group key  %s", err)
	}
	newGroup := storageClientV2.CreateGroupRequest{
		Name:              "TestGroup1" + uuid.New().String(),
		PublicKey:         encryptionKeyPair.Public.Material,
		EncryptedGroupKey: eak,
	}
	response, err := StorageClient.CreateGroup(testCtx, newGroup)
	if err != nil {
		t.Fatalf("Failed to create group \n Group( %+v) \n error %+v", newGroup, err)
	}
	if response.Name != newGroup.Name {
		t.Fatalf("Group name (%+v) passed in, does not match Group name (%+v) inserted for Group( %+v) \n", newGroup.Name, response.Name, newGroup)
	}
	// Attempt to delete group
	group := storageClientV2.DeleteGroupRequest{
		GroupID:   response.GroupID,
		AccountID: response.AccountID,
		ClientID:  uuid.MustParse(StorageClient.ClientID),
	}
	err = StorageClient.DeleteGroup(testCtx, group)
	if err != nil {
		t.Fatalf("Group DELETE: Group was not Deleted: %+v Error: %+v ", group, err)
	}
}

func TestListGroupsWithQueenClientForClientWithGroupsReturnsSuccess(t *testing.T) {
	registrationClient := accountClient.New(e3dbClients.ClientConfig{Host: cyclopsServiceHost}) // empty account host to make registration request
	queenClientConfig, _, err := test.MakeE3DBAccount(t, &registrationClient, uuid.New().String(), cyclopsServiceHost)
	if err != nil {
		t.Fatalf("Could not register account %s\n", err)
	}
	queenClient := storageClientV2.New(queenClientConfig)
	//Insert two Group To List
	encryptionKeyPair, err := e3dbClients.GenerateKeyPair()
	if err != nil {
		t.Errorf("Failed generating encryption key pair %s", err)
		return
	}
	eak, err := e3dbClients.EncryptPrivateKey(encryptionKeyPair.Private, queenClient.EncryptionKeys)
	if err != nil {
		t.Errorf("Failed generating encrypted group key  %s", err)
	}
	newGroup := storageClientV2.CreateGroupRequest{
		Name:              "TestGroup1" + uuid.New().String(),
		PublicKey:         encryptionKeyPair.Public.Material,
		EncryptedGroupKey: eak,
	}
	newGroup2 := storageClientV2.CreateGroupRequest{
		Name:              "TestGroup1" + uuid.New().String(),
		PublicKey:         encryptionKeyPair.Public.Material,
		EncryptedGroupKey: eak,
	}
	response, err := queenClient.CreateGroup(testCtx, newGroup)
	if err != nil {
		t.Fatalf("Failed to create group \n Group( %+v) \n error %+v", newGroup, err)
	}
	if response.Name != newGroup.Name {
		t.Fatalf("Group name (%+v) passed in, does not match Group name (%+v) inserted for Group( %+v) \n", newGroup.Name, response.Name, newGroup)
	}
	groupCreatedID1 := response.GroupID
	response, err = queenClient.CreateGroup(testCtx, newGroup2)
	if err != nil {
		t.Fatalf("Failed to create group \n Group( %+v) \n error %+v", newGroup2, err)
	}
	if response.Name != newGroup2.Name {
		t.Fatalf("Group name (%+v) passed in, does not match Group name (%+v) inserted for Group( %+v) \n", newGroup2.Name, response.Name, newGroup2)
	}
	groupCreatedID2 := response.GroupID
	listRequest := storageClientV2.ListGroupsRequest{
		ClientID:  uuid.MustParse(queenClient.ClientID),
		NextToken: 0,
		Max:       10,
	}
	responseList, err := queenClient.ListGroups(testCtx, listRequest)

	if err != nil {
		t.Fatalf("Failed to list Group: Response( %+v) \n error %+v", responseList, err)
	}
	for _, groupID := range []uuid.UUID{groupCreatedID1, groupCreatedID2} {
		var found bool = false
		for _, group := range responseList.Groups {
			if group.GroupID == groupID {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("Failed to list correct Group: Response( %+v) GroupID: %+v \n", responseList, groupID)
		}
	}

}

func TestListGroupsWithQueenClientAllAccountReturnsSuccess(t *testing.T) {
	registrationClient := accountClient.New(e3dbClients.ClientConfig{Host: cyclopsServiceHost})
	queenClientInfo, createAccountResponse, err := test.MakeE3DBAccount(t, &registrationClient, uuid.New().String(), cyclopsServiceHost)
	if err != nil {
		t.Fatalf("Error %s making new account", err)
	}
	queenClientInfo.Host = cyclopsServiceHost
	accountToken := createAccountResponse.AccountServiceToken
	queenClient := storageClientV2.New(queenClientInfo)
	queenClient2 := storageClientV2.New(queenClientInfo)
	encryptionKeyPair, err := e3dbClients.GenerateKeyPair()
	if err != nil {
		t.Fatalf("error %s creating account registration token using %+v %+v", err, queenClient, accountToken)
	}
	eak, err := e3dbClients.EncryptPrivateKey(encryptionKeyPair.Private, queenClient2.EncryptionKeys)
	if err != nil {
		t.Errorf("Failed generating encrypted group key  %s", err)
	}
	// Create Another Accouunt under the queen client to list groups, Each create a group
	group := storageClientV2.CreateGroupRequest{
		Name:              "TestGroup1" + uuid.New().String(),
		PublicKey:         encryptionKeyPair.Public.Material,
		EncryptedGroupKey: eak,
	}
	response, err := queenClient2.CreateGroup(testCtx, group)
	if err != nil {
		t.Fatalf("Failed to create group \n Group( %+v) \n error %+v", group, err)
	}
	if response.Name != group.Name {
		t.Fatalf("Group name (%+v) passed in, does not match Group name (%+v) inserted for Group( %+v) \n", group.Name, response.Name, group)
	}
	groupCreatedID1 := response.GroupID
	eak, err = e3dbClients.EncryptPrivateKey(encryptionKeyPair.Private, queenClient.EncryptionKeys)
	if err != nil {
		t.Errorf("Failed generating encrypted group key  %s", err)
	}
	group = storageClientV2.CreateGroupRequest{
		Name:              "TestGroup1" + uuid.New().String(),
		PublicKey:         encryptionKeyPair.Public.Material,
		EncryptedGroupKey: eak,
	}
	response, err = queenClient.CreateGroup(testCtx, group)
	if err != nil {
		t.Fatalf("Failed to create group \n Group( %+v) \n error %+v", group, err)
	}
	if response.Name != group.Name {
		t.Fatalf("Group name (%+v) passed in, does not match Group name (%+v) inserted for Group( %+v) \n", group.Name, response.Name, group)
	}
	groupCreatedID2 := response.GroupID
	// List The Groups Under the Account
	listRequest := storageClientV2.ListGroupsRequest{}
	responseList, err := queenClient.ListGroups(testCtx, listRequest)
	if err != nil {
		t.Fatalf("Failed to list Group: Response( %+v) \n error %+v", responseList, err)
	}
	for _, groupID := range []uuid.UUID{groupCreatedID1, groupCreatedID2} {
		var found bool = false
		for _, group := range responseList.Groups {
			if group.GroupID == groupID {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("Failed to list correct Group: Response( %+v) GroupID: %+v \n", responseList, groupID)
		}
	}

}

func TestListGroupsWithClientForClientWithGroupsReturnsSuccess(t *testing.T) {
	registrationClient := accountClient.New(e3dbClients.ClientConfig{Host: cyclopsServiceHost})
	queenClientInfo, createAccountResponse, err := test.MakeE3DBAccount(t, &registrationClient, uuid.New().String(), cyclopsServiceHost)
	if err != nil {
		t.Fatalf("Error %s making new account", err)
	}
	queenClientInfo.Host = cyclopsServiceHost
	accountToken := createAccountResponse.AccountServiceToken
	queenAccountClient := accountClient.New(queenClientInfo)
	registrationToken, err := test.CreateRegistrationToken(&queenAccountClient, accountToken)
	if err != nil {
		t.Fatalf("error %s creating account registration token using %+v %+v", err, queenAccountClient, accountToken)
	}

	reg, ClientConfig, err := test.RegisterClient(testCtx, ClientServiceHost, registrationToken, "name")
	if err != nil {
		t.Fatalf("Error registering Client %+v %+v %+v ", reg, err, ClientConfig)
	}
	ClientConfig.Host = cyclopsServiceHost
	regClient := storageClientV2.New(ClientConfig)

	//Create A group
	encryptionKeyPair, err := e3dbClients.GenerateKeyPair()
	eak, err := e3dbClients.EncryptPrivateKey(encryptionKeyPair.Private, regClient.EncryptionKeys)
	if err != nil {
		t.Errorf("Failed generating encrypted group key  %s", err)
	}
	group := storageClientV2.CreateGroupRequest{
		Name:              "TestGroup1" + uuid.New().String(),
		PublicKey:         encryptionKeyPair.Public.Material,
		EncryptedGroupKey: eak,
	}
	response, err := regClient.CreateGroup(testCtx, group)
	if err != nil {
		t.Fatalf("Failed to create group \n Group( %+v) \n error %+v", group, err)
	}
	if response.Name != group.Name {
		t.Fatalf("Group name (%+v) passed in, does not match Group name (%+v) inserted for Group( %+v) \n", group.Name, response.Name, group)
	}
	groupCreatedID1 := response.GroupID
	listRequest := storageClientV2.ListGroupsRequest{}
	responseList, err := regClient.ListGroups(testCtx, listRequest)
	if err != nil {
		t.Fatalf("Group LIST: Group was Not Found: %+v Error: %+v ", responseList, err)
	}
	for _, groupID := range []uuid.UUID{groupCreatedID1} {
		var found bool = false
		for _, group := range responseList.Groups {
			if group.GroupID == groupID {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("Failed to list correct Group: Response( %+v) GroupID: %+v \n", responseList, groupID)
		}
	}

}
func TestListGroupsWithQueenClientForClientWithGroupsFilteredByGroupNameReturnsOnlyOneGroupSuccess(t *testing.T) {
	registrationClient := accountClient.New(e3dbClients.ClientConfig{Host: cyclopsServiceHost})
	queenClientInfo, _, err := e3dbTest.MakeE3DBAccount(t, &registrationClient, uuid.New().String(), cyclopsServiceHost)
	if err != nil {
		t.Fatalf("Error %s making new account", err)
	}
	queenClientInfo.Host = cyclopsServiceHost
	queenClient := New(queenClientInfo)
	//Insert two Group To List
	encryptionKeyPair, err := e3dbClients.GenerateKeyPair()
	if err != nil {
		t.Errorf("Failed generating encryption key pair %s", err)
		return
	}
	newGroup := CreateGroupRequest{
		Name:              "TestGroup1" + uuid.New().String(),
		PublicKey:         encryptionKeyPair.Public.Material,
		EncryptedGroupKey: encryptionKeyPair.Private.Material,
	}
	newGroup2 := CreateGroupRequest{
		Name:              "TestGroup1" + uuid.New().String(),
		PublicKey:         encryptionKeyPair.Public.Material,
		EncryptedGroupKey: encryptionKeyPair.Private.Material,
	}
	response, err := queenClient.CreateGroup(testCtx, newGroup)
	if err != nil {
		t.Fatalf("Failed to create group \n Group( %+v) \n error %+v", newGroup, err)
	}
	if response.Name != newGroup.Name {
		t.Fatalf("Group name (%+v) passed in, does not match Group name (%+v) inserted for Group( %+v) \n", newGroup.Name, response.Name, newGroup)
	}
	groupCreatedID1 := response.GroupID
	response, err = queenClient.CreateGroup(testCtx, newGroup2)
	if err != nil {
		t.Fatalf("Failed to create group \n Group( %+v) \n error %+v", newGroup2, err)
	}
	if response.Name != newGroup2.Name {
		t.Fatalf("Group name (%+v) passed in, does not match Group name (%+v) inserted for Group( %+v) \n", newGroup2.Name, response.Name, newGroup2)
	}
	listRequest := ListGroupsRequest{
		GroupNames: []string{response.Name},
		ClientID:   uuid.MustParse(queenClient.ClientID),
		NextToken:  0,
		Max:        10,
	}
	responseList, err := queenClient.ListGroups(testCtx, listRequest)
	if err != nil {
		t.Fatalf("Failed to list Group: Response( %+v) \n error %+v", responseList, err)
	}

	if responseList.Groups[0].GroupID != groupCreatedID1 {
		t.Fatalf("Failed to filter by group name: response: (%+v), group (%+v)", responseList, groupCreatedID1)
	}

}
func TestListGroupsWithQueenClientForClientWithGroupsFilteredByGroupNameReturnsOnlyAllGroupSuccess(t *testing.T) {
	registrationClient := accountClient.New(e3dbClients.ClientConfig{Host: cyclopsServiceHost})
	queenClientInfo, _, err := e3dbTest.MakeE3DBAccount(t, &registrationClient, uuid.New().String(), cyclopsServiceHost)
	if err != nil {
		t.Fatalf("Error %s making new account", err)
	}
	queenClientInfo.Host = cyclopsServiceHost
	queenClient := New(queenClientInfo)
	//Insert two Group To List
	encryptionKeyPair, err := e3dbClients.GenerateKeyPair()
	if err != nil {
		t.Errorf("Failed generating encryption key pair %s", err)
		return
	}
	newGroup := CreateGroupRequest{
		Name:              "TestGroup1" + uuid.New().String(),
		PublicKey:         encryptionKeyPair.Public.Material,
		EncryptedGroupKey: encryptionKeyPair.Private.Material,
	}
	newGroup2 := CreateGroupRequest{
		Name:              "TestGroup1" + uuid.New().String(),
		PublicKey:         encryptionKeyPair.Public.Material,
		EncryptedGroupKey: encryptionKeyPair.Private.Material,
	}
	response, err := queenClient.CreateGroup(testCtx, newGroup)
	if err != nil {
		t.Fatalf("Failed to create group \n Group( %+v) \n error %+v", newGroup, err)
	}
	if response.Name != newGroup.Name {
		t.Fatalf("Group name (%+v) passed in, does not match Group name (%+v) inserted for Group( %+v) \n", newGroup.Name, response.Name, newGroup)
	}
	groupCreatedID1 := response.GroupID
	response, err = queenClient.CreateGroup(testCtx, newGroup2)
	if err != nil {
		t.Fatalf("Failed to create group \n Group( %+v) \n error %+v", newGroup2, err)
	}
	if response.Name != newGroup2.Name {
		t.Fatalf("Group name (%+v) passed in, does not match Group name (%+v) inserted for Group( %+v) \n", newGroup2.Name, response.Name, newGroup2)
	}
	groupCreatedID2 := response.GroupID
	listRequest := ListGroupsRequest{
		GroupNames: []string{newGroup.Name, newGroup2.Name},
		ClientID:   uuid.MustParse(queenClient.ClientID),
		NextToken:  0,
		Max:        10,
	}
	responseList, err := queenClient.ListGroups(testCtx, listRequest)
	if err != nil {
		t.Fatalf("Failed to list Group: Response( %+v) \n error %+v", responseList, err)
	}
	for _, groupID := range []uuid.UUID{groupCreatedID1, groupCreatedID2} {
		var found bool = false
		for _, group := range responseList.Groups {
			if group.GroupID == groupID {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("Failed to list correct Group: Response( %+v) GroupID: %+v \n", responseList, groupID)
		}
	}
}
func TestListGroupsWithClientForClientWithGroupsFilteredByGroupNameReturnsOneGroupSuccess(t *testing.T) {
	registrationClient := accountClient.New(e3dbClients.ClientConfig{Host: cyclopsServiceHost})
	queenClientInfo, createAccountResponse, err := e3dbTest.MakeE3DBAccount(t, &registrationClient, uuid.New().String(), cyclopsServiceHost)
	if err != nil {
		t.Fatalf("Error %s making new account", err)
	}
	queenClientInfo.Host = cyclopsServiceHost
	accountToken := createAccountResponse.AccountServiceToken
	queenAccountClient := accountClient.New(queenClientInfo)
	registrationToken, err := e3dbTest.CreateRegistrationToken(&queenAccountClient, accountToken)
	if err != nil {
		t.Fatalf("error %s creating account registration token using %+v %+v", err, queenAccountClient, accountToken)
	}

	reg, ClientConfig, err := e3dbTest.RegisterClient(testCtx, ClientServiceHost, registrationToken, "name")
	if err != nil {
		t.Fatalf("Error registering Client %+v %+v %+v ", reg, err, ClientConfig)
	}
	ClientConfig.Host = cyclopsServiceHost
	regClient := New(ClientConfig)

	//Create A group
	encryptionKeyPair, err := e3dbClients.GenerateKeyPair()
	group := CreateGroupRequest{
		Name:              "TestGroup1" + uuid.New().String(),
		PublicKey:         encryptionKeyPair.Public.Material,
		EncryptedGroupKey: encryptionKeyPair.Private.Material,
	}
	group2 := CreateGroupRequest{
		Name:              "TestGroup1" + uuid.New().String(),
		PublicKey:         encryptionKeyPair.Public.Material,
		EncryptedGroupKey: encryptionKeyPair.Private.Material,
	}

	response, err := regClient.CreateGroup(testCtx, group)
	if err != nil {
		t.Fatalf("Failed to create group \n Group( %+v) \n error %+v", group, err)
	}
	if response.Name != group.Name {
		t.Fatalf("Group name (%+v) passed in, does not match Group name (%+v) inserted for Group( %+v) \n", group.Name, response.Name, group)
	}
	groupCreatedID1 := response.GroupID
	response, err = regClient.CreateGroup(testCtx, group2)
	if err != nil {
		t.Fatalf("Failed to create group \n Group( %+v) \n error %+v", group, err)
	}
	if response.Name != group2.Name {
		t.Fatalf("Group name (%+v) passed in, does not match Group name (%+v) inserted for Group( %+v) \n", group.Name, response.Name, group)
	}
	listRequest := ListGroupsRequest{
		GroupNames: []string{group.Name},
	}
	responseList, err := regClient.ListGroups(testCtx, listRequest)

	if err != nil {
		t.Fatalf("Group LIST: Group was Not Found: %+v Error: %+v", responseList, err)
	}
	if responseList.Groups[0].GroupID != groupCreatedID1 {
		t.Fatalf("Failed to filter by group name: response: (%+v), group (%+v)", responseList, groupCreatedID1)
	}

}
func TestListGroupsWithClientForClientWithGroupsFilteredByGroupNameReturnsAllGroupSuccess(t *testing.T) {
	registrationClient := accountClient.New(e3dbClients.ClientConfig{Host: cyclopsServiceHost})
	queenClientInfo, createAccountResponse, err := e3dbTest.MakeE3DBAccount(t, &registrationClient, uuid.New().String(), cyclopsServiceHost)
	if err != nil {
		t.Fatalf("Error %s making new account", err)
	}
	queenClientInfo.Host = cyclopsServiceHost
	accountToken := createAccountResponse.AccountServiceToken
	queenAccountClient := accountClient.New(queenClientInfo)
	registrationToken, err := e3dbTest.CreateRegistrationToken(&queenAccountClient, accountToken)
	if err != nil {
		t.Fatalf("error %s creating account registration token using %+v %+v", err, queenAccountClient, accountToken)
	}

	reg, ClientConfig, err := e3dbTest.RegisterClient(testCtx, ClientServiceHost, registrationToken, "name")
	if err != nil {
		t.Fatalf("Error registering Client %+v %+v %+v ", reg, err, ClientConfig)
	}
	ClientConfig.Host = cyclopsServiceHost
	regClient := New(ClientConfig)

	//Create A group
	encryptionKeyPair, err := e3dbClients.GenerateKeyPair()
	group := CreateGroupRequest{
		Name:              "TestGroup1" + uuid.New().String(),
		PublicKey:         encryptionKeyPair.Public.Material,
		EncryptedGroupKey: encryptionKeyPair.Private.Material,
	}
	group2 := CreateGroupRequest{
		Name:              "TestGroup1" + uuid.New().String(),
		PublicKey:         encryptionKeyPair.Public.Material,
		EncryptedGroupKey: encryptionKeyPair.Private.Material,
	}

	response, err := regClient.CreateGroup(testCtx, group)
	if err != nil {
		t.Fatalf("Failed to create group \n Group( %+v) \n error %+v", group, err)
	}
	if response.Name != group.Name {
		t.Fatalf("Group name (%+v) passed in, does not match Group name (%+v) inserted for Group( %+v) \n", group.Name, response.Name, group)
	}
	groupCreatedID1 := response.GroupID
	response, err = regClient.CreateGroup(testCtx, group2)
	if err != nil {
		t.Fatalf("Failed to create group \n Group( %+v) \n error %+v", group, err)
	}
	if response.Name != group2.Name {
		t.Fatalf("Group name (%+v) passed in, does not match Group name (%+v) inserted for Group( %+v) \n", group.Name, response.Name, group)
	}
	groupCreatedID2 := response.GroupID
	listRequest := ListGroupsRequest{
		GroupNames: []string{group.Name, group2.Name},
	}
	responseList, err := regClient.ListGroups(testCtx, listRequest)

	if err != nil {
		t.Fatalf("Group LIST: Group was Not Found: %+v Error: %+v ", responseList, err)
	}
	for _, groupID := range []uuid.UUID{groupCreatedID1, groupCreatedID2} {
		var found bool = false
		for _, group := range responseList.Groups {
			if group.GroupID == groupID {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("Failed to list correct Group: Response( %+v) GroupID: %+v \n", responseList, groupID)
		}
	}
}

func TestCreateGroupMembershipKey(t *testing.T) {
	// Create Clients for this test
	registrationClient := accountClient.New(e3dbClients.ClientConfig{Host: cyclopsServiceHost})
	queenClientInfo, createAccountResponse, err := test.MakeE3DBAccount(t, &registrationClient, uuid.New().String(), cyclopsServiceHost)
	if err != nil {
		t.Fatalf("Error %s making new account", err)
	}
	queenClientInfo.Host = cyclopsServiceHost
	accountToken := createAccountResponse.AccountServiceToken
	queenAccountClient := accountClient.New(queenClientInfo)
	registrationToken, err := test.CreateRegistrationToken(&queenAccountClient, accountToken)
	if err != nil {
		t.Fatalf("error %s creating account registration token using %+v %+v", err, queenAccountClient, accountToken)
	}
	reg, ClientConfig, err := test.RegisterClient(testCtx, ClientServiceHost, registrationToken, "name")
	if err != nil {
		t.Fatalf("Error registering Client %+v %+v %+v ", reg, err, ClientConfig)
	}
	ClientConfig.Host = cyclopsServiceHost
	groupMemberToAdd := storageClientV2.New(ClientConfig)
	queenClient := storageClientV2.New(queenClientInfo)
	// Generate a Key pair for the group
	encryptionKeyPair, err := e3dbClients.GenerateKeyPair()
	if err != nil {
		t.Errorf("Failed generating encryption key pair %s", err)
		return
	}
	// encrypt the created private key for groups
	eak, err := e3dbClients.EncryptPrivateKey(encryptionKeyPair.Private, queenClient.EncryptionKeys)
	if err != nil {
		t.Errorf("Failed generating encrypted group key  %s", err)
	}
	// Create a new group to give membership key for the client
	newGroup := storageClientV2.CreateGroupRequest{
		Name:              "TestGroup1" + uuid.New().String(),
		PublicKey:         encryptionKeyPair.Public.Material,
		EncryptedGroupKey: eak,
	}
	response, err := queenClient.CreateGroup(testCtx, newGroup)
	if err != nil {
		t.Fatalf("Failed to create group \n Group( %+v) \n error %+v", newGroup, err)
	}
	if response.Name != newGroup.Name {
		t.Fatalf("Group name (%+v) passed in, does not match Group name (%+v) inserted for Group( %+v) \n", newGroup.Name, response.Name, newGroup)
	}
	//Create a request to create a new membership key
	membershipKeyRequest := storageClientV2.CreateMembershipKeyRequest{
		GroupAdminID:      queenClient.ClientID,
		NewMemberID:       groupMemberToAdd.ClientID,
		EncryptedGroupKey: response.EncryptedGroupKey,
		ShareePublicKey:   queenClient.EncryptionKeys.Public.Material,
	}
	membershipKeyResponse, err := queenClient.CreateGroupMembershipKey(testCtx, membershipKeyRequest)
	if err != nil {
		t.Fatalf("Failed to create membership key \n response %+v \n error %+v", membershipKeyResponse, err)
	}
	// Verify that the group membership key for the client matches the output for the group raw privat key above
	rawEncryptionKey, err := e3dbClients.DecodeSymmetricKey(groupMemberToAdd.EncryptionKeys.Private.Material)
	if err != nil {
		t.Fatalf("Client to add to group Private key was not decoded correctly \n Client: %+v, err: %+v ", groupMemberToAdd, err)
	}
	groupKey, err := e3dbClients.DecryptEAK(membershipKeyResponse, queenClient.EncryptionKeys.Public.Material, rawEncryptionKey)
	if err != nil {
		t.Fatalf("The membership key was not decrypted correctly: MembershipKey: %+v, queenClient : %+v, group member to add private key: %+v ", membershipKeyResponse, queenClient.EncryptionKeys.Public.Material, rawEncryptionKey)

	}
	rawGroupPrivateKey := e3dbClients.Base64Encode(groupKey[:])
	if rawGroupPrivateKey != encryptionKeyPair.Private.Material {
		t.Fatalf("Raw Private key does not match: raw %+v client's raw private key %+v", encryptionKeyPair.Private.Material, rawGroupPrivateKey)
	}
}
func TestAddOneGroupMemberWithValidInputReturnsSuccess(t *testing.T) {
	// Create Clients for this test
	registrationClient := accountClient.New(e3dbClients.ClientConfig{Host: cyclopsServiceHost})
	queenClientInfo, createAccountResponse, err := test.MakeE3DBAccount(t, &registrationClient, uuid.New().String(), cyclopsServiceHost)
	if err != nil {
		t.Fatalf("Error %s making new account", err)
	}
	queenClientInfo.Host = cyclopsServiceHost
	accountToken := createAccountResponse.AccountServiceToken
	queenAccountClient := accountClient.New(queenClientInfo)
	registrationToken, err := test.CreateRegistrationToken(&queenAccountClient, accountToken)
	if err != nil {
		t.Fatalf("error %s creating account registration token using %+v %+v", err, queenAccountClient, accountToken)
	}
	reg, ClientConfig, err := test.RegisterClient(testCtx, ClientServiceHost, registrationToken, "name")
	if err != nil {
		t.Fatalf("Error registering Client %+v %+v %+v ", reg, err, ClientConfig)
	}
	ClientConfig.Host = cyclopsServiceHost
	groupMemberToAdd := storageClientV2.New(ClientConfig)
	queenClient := storageClientV2.New(queenClientInfo)
	// Generate a Key pair for the group
	encryptionKeyPair, err := e3dbClients.GenerateKeyPair()
	if err != nil {
		t.Errorf("Failed generating encryption key pair %s", err)
		return
	}
	// encrypt the created private key for groups
	eak, err := e3dbClients.EncryptPrivateKey(encryptionKeyPair.Private, queenClient.EncryptionKeys)
	if err != nil {
		t.Errorf("Failed generating encrypted group key  %s", err)
	}
	// Create a new group to give membership key for the client
	newGroup := storageClientV2.CreateGroupRequest{
		Name:              "TestGroup1" + uuid.New().String(),
		PublicKey:         encryptionKeyPair.Public.Material,
		EncryptedGroupKey: eak,
	}
	response, err := queenClient.CreateGroup(testCtx, newGroup)
	if err != nil {
		t.Fatalf("Failed to create group \n Group( %+v) \n error %+v", newGroup, err)
	}
	if response.Name != newGroup.Name {
		t.Fatalf("Group name (%+v) passed in, does not match Group name (%+v) inserted for Group( %+v) \n", newGroup.Name, response.Name, newGroup)
	}
	//Create a request to create a new membership key
	membershipKeyRequest := storageClientV2.CreateMembershipKeyRequest{
		GroupAdminID:      queenClient.ClientID,
		NewMemberID:       groupMemberToAdd.ClientID,
		EncryptedGroupKey: response.EncryptedGroupKey,
		ShareePublicKey:   queenClient.EncryptionKeys.Public.Material,
	}
	membershipKeyResponse, err := queenClient.CreateGroupMembershipKey(testCtx, membershipKeyRequest)
	if err != nil {
		t.Fatalf("Failed to create membership key \n response %+v \n error %+v", membershipKeyResponse, err)
	}

	// Add client to group
	groupMemberCapabilities := []string{storageClientV2.ShareContentGroupCapability, storageClientV2.ReadContentGroupCapability}
	memberRequest := []storageClientV2.GroupMember{}
	memberRequest = append(memberRequest,
		storageClientV2.GroupMember{
			ClientID:        uuid.MustParse(groupMemberToAdd.ClientID),
			MembershipKey:   membershipKeyResponse,
			CapabilityNames: groupMemberCapabilities})

	addMemberRequest := storageClientV2.AddGroupMembersRequest{
		GroupID:      response.GroupID,
		GroupMembers: memberRequest,
	}
	addToGroupResponse, err := queenClient.AddGroupMembers(testCtx, addMemberRequest)
	if err != nil {
		t.Fatalf("Failed to Add Group Member to Group: Request:  %+v Err: %+v", addMemberRequest, err)
	}
	for _, requestGroupMember := range addMemberRequest.GroupMembers {
		var found bool
		for _, responseGroupMember := range *addToGroupResponse {
			if responseGroupMember.ClientID == requestGroupMember.ClientID {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("Failed to add correct Group Members: Response( %+v) \n", addToGroupResponse)
		}
	}

}
func TestAddBulkGroupMemberWithValidInputReturnsSuccess(t *testing.T) {
	// Create Clients for this test
	registrationClient := accountClient.New(e3dbClients.ClientConfig{Host: cyclopsServiceHost})
	queenClientInfo, createAccountResponse, err := test.MakeE3DBAccount(t, &registrationClient, uuid.New().String(), cyclopsServiceHost)
	if err != nil {
		t.Fatalf("Error %s making new account", err)
	}
	queenClientInfo.Host = cyclopsServiceHost
	accountToken := createAccountResponse.AccountServiceToken
	queenAccountClient := accountClient.New(queenClientInfo)
	registrationToken, err := test.CreateRegistrationToken(&queenAccountClient, accountToken)
	if err != nil {
		t.Fatalf("error %s creating account registration token using %+v %+v", err, queenAccountClient, accountToken)
	}
	reg, ClientConfig, err := test.RegisterClient(testCtx, ClientServiceHost, registrationToken, "name")
	if err != nil {
		t.Fatalf("Error registering Client %+v %+v %+v ", reg, err, ClientConfig)
	}
	reg, ClientConfig2, err := test.RegisterClient(testCtx, ClientServiceHost, registrationToken, "name")
	if err != nil {
		t.Fatalf("Error registering Client %+v %+v %+v ", reg, err, ClientConfig)
	}
	ClientConfig.Host = cyclopsServiceHost
	ClientConfig2.Host = cyclopsServiceHost
	// Clients to Add to Group
	groupMemberToAdd1 := storageClientV2.New(ClientConfig)
	groupMemberToAdd2 := storageClientV2.New(ClientConfig2)
	queenClient := storageClientV2.New(queenClientInfo)
	// Generate a Key pair for the group
	encryptionKeyPair, err := e3dbClients.GenerateKeyPair()
	if err != nil {
		t.Errorf("Failed generating encryption key pair %s", err)
		return
	}
	// encrypt the created private key for groups
	eak, err := e3dbClients.EncryptPrivateKey(encryptionKeyPair.Private, queenClient.EncryptionKeys)
	if err != nil {
		t.Errorf("Failed generating encrypted group key  %s", err)
	}
	// Create a new group to give membership key for the client
	newGroup := storageClientV2.CreateGroupRequest{
		Name:              "TestGroup1" + uuid.New().String(),
		PublicKey:         encryptionKeyPair.Public.Material,
		EncryptedGroupKey: eak,
	}
	response, err := queenClient.CreateGroup(testCtx, newGroup)
	if err != nil {
		t.Fatalf("Failed to create group \n Group( %+v) \n error %+v", newGroup, err)
	}
	if response.Name != newGroup.Name {
		t.Fatalf("Group name (%+v) passed in, does not match Group name (%+v) inserted for Group( %+v) \n", newGroup.Name, response.Name, newGroup)
	}
	//Create a request to create a new membership key for client1
	membershipKeyRequest := storageClientV2.CreateMembershipKeyRequest{
		GroupAdminID:      queenClient.ClientID,
		NewMemberID:       groupMemberToAdd1.ClientID,
		EncryptedGroupKey: response.EncryptedGroupKey,
		ShareePublicKey:   queenClient.EncryptionKeys.Public.Material,
	}
	membershipKeyResponse, err := queenClient.CreateGroupMembershipKey(testCtx, membershipKeyRequest)
	if err != nil {
		t.Fatalf("Failed to create membership key \n response %+v \n error %+v", membershipKeyResponse, err)
	}
	//Create a request to create a new membership key for client2
	membershipKeyRequest2 := storageClientV2.CreateMembershipKeyRequest{
		GroupAdminID:      queenClient.ClientID,
		NewMemberID:       groupMemberToAdd2.ClientID,
		EncryptedGroupKey: response.EncryptedGroupKey,
		ShareePublicKey:   queenClient.EncryptionKeys.Public.Material,
	}
	membershipKeyResponse2, err := queenClient.CreateGroupMembershipKey(testCtx, membershipKeyRequest2)
	if err != nil {
		t.Fatalf("Failed to create membership key \n response %+v \n error %+v", membershipKeyResponse, err)
	}
	// Add clients  to group
	groupMemberCapabilities := []string{storageClientV2.ShareContentGroupCapability, storageClientV2.ReadContentGroupCapability}
	memberRequest := []storageClientV2.GroupMember{}
	//Adding First Client to Request
	memberRequest = append(memberRequest,
		storageClientV2.GroupMember{
			ClientID:        uuid.MustParse(groupMemberToAdd1.ClientID),
			MembershipKey:   membershipKeyResponse,
			CapabilityNames: groupMemberCapabilities})
	//Adding Second client to request
	memberRequest = append(memberRequest,
		storageClientV2.GroupMember{
			ClientID:        uuid.MustParse(groupMemberToAdd2.ClientID),
			MembershipKey:   membershipKeyResponse2,
			CapabilityNames: groupMemberCapabilities})
	addMemberRequest := storageClientV2.AddGroupMembersRequest{
		GroupID:      response.GroupID,
		GroupMembers: memberRequest,
	}
	AddToGroupResponse, err := queenClient.AddGroupMembers(testCtx, addMemberRequest)
	if err != nil {
		t.Fatalf("Failed to Add Group Member to Group: Request:  %+v Err: %+v", addMemberRequest, err)
	}
	for _, requestGroupMember := range addMemberRequest.GroupMembers {
		var found bool
		for _, responseGroupMember := range *AddToGroupResponse {
			if responseGroupMember.ClientID == requestGroupMember.ClientID {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("Failed to add correct Group Members: Response( %+v) \n", AddToGroupResponse)
		}
	}
}
