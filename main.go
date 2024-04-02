package main

import (
	"bufio"
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
	"syscall"

	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
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

func printHelp() {
	fmt.Println("keyval local database")
	fmt.Println("")
	fmt.Println("Usage:")
	fmt.Println("- keyval set {keyName} {keyValue}: set a key-value pair")
	fmt.Println("- keyval sset {keyName}: set a sensitive key-value pair; prompts for a secret at the terminal")
	fmt.Println("- keyval fset {fileName}: set a key-value pair, where the value is the content of a file")
	fmt.Println("- some-command | keyval set your-key: set a key-value pair, where the value is from stdin")
	fmt.Println("- keyval get {keyName}: print a value from a key")
	fmt.Println("- keyval list: list available keys")
	fmt.Println("- keyval list {prefix}: list available keys with a given prefix")
	fmt.Println("- keyval delete {keyname}: delete a key-value pair")
	fmt.Println("- keyval help: display this message")
}

func dispatcher() {
	if len(os.Args) == 1 {
		printHelp()
		return
	}
	mainCommand := os.Args[1]
	key := readKeyFromEnvironment()
	if mainCommand == "set" {
		// Is this a normal set or a stdin set?
		// A normal set will have len(os.Args) == 4, stdin set will have len(os.Args) == 3
		if len(os.Args) == 4 {
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
		} else if len(os.Args) == 3 {
			scanner := bufio.NewScanner(os.Stdin)
			lines := []string{}
			for scanner.Scan() {
				line := scanner.Text()
				lines = append(lines, line)
			}
			if err := scanner.Err(); err != nil {
				log.Fatal(err)
			}
			dataValue := strings.Join(lines, "\n")
			dataKey := os.Args[2]
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
		}
	} else if mainCommand == "help" {
		printHelp()
	} else if mainCommand == "fset" {
		dataKey := os.Args[2]
		dataFilePath := os.Args[3]
		content := readDb()
		dbData := unmarshalDb(content)
		decryptedData := make(map[string]string)
		for k, v := range dbData {
			decryptedKey := decrypt(k, key)
			decryptedValue := decrypt(v, key)
			decryptedData[decryptedKey] = decryptedValue
		}
		// Read the given file
		file, err := os.Open(dataFilePath)
		if err != nil {
			log.Fatal(err)
		}
		b, err := io.ReadAll(file)
		if err != nil {
			log.Fatal(err)
		}
		// Attempt to cast contents to string
		fileStringContents := string(b)
		// Do not trim trailing newlines
		decryptedData[dataKey] = fileStringContents
		encryptedData := make(map[string]string)
		for k, v := range decryptedData {
			encryptedKey := encrypt(k, key)
			encryptedValue := encrypt(v, key)
			encryptedData[encryptedKey] = encryptedValue
		}
		content = marshalDb(encryptedData)
		writeDb(content)
	} else if mainCommand == "sset" {
		dataKey := os.Args[2]
		fmt.Print("Sensitive value: ")
		bytepw, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			log.Fatal(err)
		}
		dataValue := string(bytepw)
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
		stringToPrint := decryptedData[dataKey]
		// Trim trailing newlines
		stringToPrint = strings.Trim(stringToPrint, "\n")
		fmt.Println(stringToPrint)
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
		// Check if this is a basic list command or if it's a prefix list command
		if len(os.Args) == 3 {
			// Prefix list command
			prefix := os.Args[2]
			for _, s := range dbKeys {
				if strings.HasPrefix(s, prefix) {
					fmt.Println(s)
				}
			}
			return
		} else {
			for _, s := range dbKeys {
				fmt.Println(s)
			}
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
