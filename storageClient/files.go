package storageClient

import (
	"os"
	"net/http"
)

func (c *StorageClient) UploadFile(url string, encryptedFileName string, checksum string, size int) (int, error){
	file, err := os.Open(encryptedFileName)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	req, err := http.NewRequest("PUT", url, file)
	if err != nil {
		return 0, nil
	}
	req.Header.Set("Content-MD5", checksum)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.ContentLength = int64(size)
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.StatusCode, err
	}
	return 0, nil
}
