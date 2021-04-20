package storageClient

import (
	"fmt"
	"io"
	"net/http"
	"os"
)

func (c *StorageClient) UploadFile(url string, encryptedFileName string, checksum string, size int) (int, error) {
	file, err := os.Open(encryptedFileName)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	req, err := http.NewRequest("PUT", url, file)
	if err != nil {
		return 0, err
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

func (c *StorageClient) DownloadFile(url string, encryptedFileName string) (string, error) {
	file, err := os.Create(encryptedFileName)
	if err != nil {
		return fmt.Sprintf("e3db-clients-go:DownloadFile: error creating file %s", encryptedFileName), err
	}
	defer file.Close()
	resp, err := http.Get(url)
	if err != nil {
		return "e3db-clients-go:DownloadFile: get failed", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Sprintf("e3db-clients-go:DownloadFile: status is %d", resp.StatusCode), nil
	}
	_, err = io.Copy(file, resp.Body)
	if err != nil {
		return fmt.Sprintf("e3db-clients-go:DownloadFile: error copying response to %s", encryptedFileName), err
	}
	return "", nil
}
