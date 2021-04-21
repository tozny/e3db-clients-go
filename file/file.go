package file

import (
	"fmt"
	"io"
	"net/http"
	"os"
)

type UploadRequest struct {
	URL               string
	EncryptedFileName string
	Checksum          string
	Size              int
}

type DownloadRequest struct {
	URL               string
	EncryptedFileName string
}

// UploadFile streams the contents of the encrypted file and puts it at the requested URL
func UploadFile(uploadReq UploadRequest) (int, error) {
	file, err := os.Open(uploadReq.EncryptedFileName)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	req, err := http.NewRequest("PUT", uploadReq.URL, file)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-MD5", uploadReq.Checksum)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.ContentLength = int64(uploadReq.Size)
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.StatusCode, err
	}
	return 0, nil
}

// DownloadFile gets the file contents from the specified URL and streams the body into the specified file
func DownloadFile(downloadReq DownloadRequest) (string, error) {
	file, err := os.Create(downloadReq.EncryptedFileName)
	if err != nil {
		return fmt.Sprintf("e3db-clients-go:DownloadFile: error creating file %s", downloadReq.EncryptedFileName), err
	}
	defer file.Close()
	resp, err := http.Get(downloadReq.URL)
	if err != nil {
		return "e3db-clients-go:DownloadFile: get failed", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Sprintf("e3db-clients-go:DownloadFile: status is %d", resp.StatusCode), nil
	}
	// reads chunks from resp.Body, writes to the encrypted file, and then repeats until the end of resp.Body
	_, err = io.Copy(file, resp.Body)
	if err != nil {
		return fmt.Sprintf("e3db-clients-go:DownloadFile: error copying response to %s", downloadReq.EncryptedFileName), err
	}
	return "", nil
}
