package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	dotfolder              = ".keyval/"
	dbFile                 = "db"
	keyEnvironmentVariable = "KEYVAL_KEY"
	recordSeparator        = "\x1e"
	unitSeparator          = "\x1f"
)

func main() {
	dispatcher()
}

func dispatcher() {
	mainCommand := os.Args[1]
	key := readKeyFromEnvironment()
	if mainCommand == "set" {
		dataKey := os.Args[2]
		dataValue := os.Args[3]
		content := readDb()
		dbData := unmarshalDb(content)
		decryptedData := make(map[string]string)
		for k, v := range dbData {
			decryptedKey := decrypt(k, key)
			decryptedValue := decrypt(v, key)
			decryptedData[decryptedKey] = decryptedValue
		}
		decryptedData[dataKey] = dataValue
		encryptedData := make(map[string]string)
		for k, v := range decryptedData {
			encryptedKey := encrypt(k, key)
			encryptedValue := encrypt(v, key)
			encryptedData[encryptedKey] = encryptedValue
		}
		content = marshalDb(encryptedData)
		writeDb(content)
	} else if mainCommand == "get" {
		dataKey := os.Args[2]
		content := readDb()
		dbData := unmarshalDb(content)
		decryptedData := make(map[string]string)
		for k, v := range dbData {
			decryptedKey := decrypt(k, key)
			decryptedValue := decrypt(v, key)
			decryptedData[decryptedKey] = decryptedValue
		}
		fmt.Println(decryptedData[dataKey])
	} else if mainCommand == "list" {
		content := readDb()
		dbData := unmarshalDb(content)
		dbKeys := []string{}
		for k, _ := range dbData {
			decryptedKey := decrypt(k, key)
			dbKeys = append(dbKeys, decryptedKey)
		}
		sort.Slice(dbKeys, func(i, j int) bool {
			return dbKeys[i] < dbKeys[j]
		})
		for _, s := range dbKeys {
			fmt.Println(s)
		}
	} else if mainCommand == "delete" {
		dataKey := os.Args[2]
		content := readDb()
		dbData := unmarshalDb(content)
		decryptedData := make(map[string]string)
		for k, v := range dbData {
			decryptedKey := decrypt(k, key)
			decryptedValue := decrypt(v, key)
			decryptedData[decryptedKey] = decryptedValue
		}
		delete(decryptedData, dataKey)
		encryptedData := make(map[string]string)
		for k, v := range decryptedData {
			encryptedKey := encrypt(k, key)
			encryptedValue := encrypt(v, key)
			encryptedData[encryptedKey] = encryptedValue
		}
		if len(encryptedData) == 0 {
			writeDb("")
		} else {
			content = marshalDb(encryptedData)
			writeDb(content)
		}
	}
}

func marshalDb(data map[string]string) string {
	var sb strings.Builder
	for k, v := range data {
		record := strings.Join([]string{k, v}, unitSeparator) + recordSeparator
		sb.WriteString(record)
	}
	dbContent := sb.String()
	dbContent = dbContent[:len(dbContent)-1]
	return dbContent
}

func unmarshalDb(content string) map[string]string {
	if content == "" {
		return map[string]string{}
	}
	records := strings.Split(content, recordSeparator)
	dbData := make(map[string]string)
	for _, record := range records {
		splitRecord := strings.Split(record, unitSeparator)
		dbData[splitRecord[0]] = splitRecord[1]
	}
	return dbData
}

func ensureDotfolder() {
	homeDirectory, err := os.UserHomeDir()
	if err != nil {
		log.Fatal(err)
	}
	dotfolderPath := filepath.Join(homeDirectory, dotfolder)
	err = os.MkdirAll(dotfolderPath, 0744)
	if err != nil {
		log.Fatal(err)
	}
}

func writeDb(content string) {
	ensureDotfolder()
	// Funny, just open it and write...
	homeDirectory, err := os.UserHomeDir()
	if err != nil {
		log.Fatal(err)
	}
	dbPath := filepath.Join(homeDirectory, dotfolder, dbFile)
	err = os.WriteFile(dbPath, []byte(content), 0744)
	if err != nil {
		log.Fatal(err)
	}
}

func readDb() string {
	ensureDotfolder()
	homeDirectory, err := os.UserHomeDir()
	if err != nil {
		log.Fatal(err)
	}
	dbPath := filepath.Join(homeDirectory, dotfolder, dbFile)
	// log.Print(dbPath)
	// Does the file already exist?
	_, err = os.Stat(dbPath)
	if err != nil {
		// If it doesn't exist, then make it
		if errors.Is(err, os.ErrNotExist) {
			// log.Print("DB doesn't exist")
			f, err := os.Create(dbPath)
			if err != nil {
				log.Fatal(err)
			}
			defer f.Close()
			// Read the new file and return its contents
			b, err := io.ReadAll(f)
			if err != nil {
				log.Fatal(err)
			}
			return string(b)
		} else {
			log.Fatal(err)
		}
	}
	// If it exists, read it normally
	// log.Print("DB appears to exist")
	f, err := os.Open(dbPath)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil {
		log.Fatal(err)
	}
	return string(b)
}

func readKeyFromEnvironment() []byte {
	key := os.Getenv(keyEnvironmentVariable)
	if key == "" {
		log.Fatalf("No value set for %s", keyEnvironmentVariable)
	}

	// Mark to 32 bytes
	// Apparently do not just pad with 0s. Use a key derivation function.
	derivedKey := argon2.IDKey([]byte(key), []byte(""), 1, 64*1024, 4, 32)

	return derivedKey
}

func encrypt(plaintext string, key []byte) string {
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatal(err)
	}

	// What the hell does this do?
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		log.Fatal(err)
	}

	cipherTextBytes := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)
	cipherText := hex.EncodeToString(cipherTextBytes)

	return cipherText
}

func decrypt(ciphertext string, key []byte) string {
	cipherTextBytes, err := hex.DecodeString(ciphertext)
	if err != nil {
		log.Fatal(err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatal(err)
	}

	nonceSize := aesGCM.NonceSize()
	nonce, cipherTextBytes := cipherTextBytes[:nonceSize], cipherTextBytes[nonceSize:]

	plainTextBytes, err := aesGCM.Open(nil, nonce, cipherTextBytes, nil)
	if err != nil {
		log.Fatal(err)
	}

	plaintext := string(plainTextBytes)

	return plaintext
}
