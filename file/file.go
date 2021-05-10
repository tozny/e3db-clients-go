package file

import (
	"fmt"
	"io"
	"io/ioutil"
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
func UploadFile(uploadReq UploadRequest) error {
	file, err := os.Open(uploadReq.EncryptedFileName)
	if err != nil {
		return err
	}
	defer file.Close()
	req, err := http.NewRequest("PUT", uploadReq.URL, file)
	if err != nil {
		return err
	}
	req.Header.Set("Content-MD5", uploadReq.Checksum)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.ContentLength = int64(uploadReq.Size)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("UploadFile: invalid status code: %d", resp.StatusCode)
	}
	return nil
}

// DownloadFile gets the file contents from the specified URL and streams the body into the specified file
func DownloadFile(downloadReq DownloadRequest) (string, error) {
	file, err := ioutil.TempFile("", downloadReq.EncryptedFileName)
	if err != nil {
		return "", err
	}
	defer file.Close()
	resp, err := http.Get(downloadReq.URL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("e3db-clients-go:DownloadFile: status is %d", resp.StatusCode)
	}
	// reads chunks from resp.Body, writes to the encrypted file, and then repeats until the end of resp.Body
	_, err = io.Copy(file, resp.Body)
	if err != nil {
		return "", err
	}
	return file.Name(), nil
}
