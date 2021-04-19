package storageClient

import (
	"os"
	"net/http"
	"fmt"
	"io"
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

func (c *StorageClient) DownloadFile(url string, encryptedFileName string) (string, error){
	fmt.Println("url in download:", url)
	file, err := os.Create(encryptedFileName)

	if err != nil {
		return "", err
	}
	defer file.Close()
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("resp is:", resp)
		fmt.Println("err is:", err)
		return "get failed", err
	}
	defer resp.Body.Close()
	fmt.Println("status code: ", resp.StatusCode)
	if resp.StatusCode != http.StatusOK {
		return "wrong status code", nil
	}
	_, err = io.Copy(file, resp.Body)
	if err != nil {
		return "", err
	}
	fmt.Println("resp:", resp)
	fmt.Println("err:", err)
	return "", err
}
