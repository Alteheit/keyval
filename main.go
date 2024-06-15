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
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
)

const (
	dotfolder                 = ".keyval/"
	dbFile                    = "db"
	keyEnvironmentVariable    = "KEYVAL_KEY"
	editorEnvironmentVariable = "EDITOR"
	recordSeparator           = "\x1e"
	unitSeparator             = "\x1f"
	ttyFd                     = "/dev/tty"
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
	fmt.Println("- keyval fset {keyName} {fileName}: set a key-value pair, where the value is the content of a file")
	fmt.Println("- some-command | keyval set your-key: set a key-value pair, where the value is from stdin")
	fmt.Println("- keyval get {keyName}: print a value from a key")
	fmt.Println("- keyval list: list available keys")
	fmt.Println("- keyval list {prefix}: list available keys with a given prefix")
	fmt.Println("- keyval delete {keyName}: delete a key-value pair")
	fmt.Println("- keyval edit {keyName}: open the contents of a key-value pair using a terminal text editor")
	fmt.Println("- keyval help: display this message")
	fmt.Println("")
	fmt.Println("Management:")
	fmt.Println("- keyval dump: dump your encrypted database to stdout")
	fmt.Println("- keyval dump {your-file}: dump your encrypted database to the given file")
	fmt.Println("- keyval restore {your-file}: restore your database from a dump")
	fmt.Println("- keyval export-decrypt {your-file}: decrypt and dump your database to the given file")
	fmt.Println("- keyval import-encrypt {your-file}: encrypt and import a database from the given file")
	fmt.Println("- keyval merge {file-1} {file-2} {output-file}: merge two encrypted keyval dumps. Walks you through resolving merge conflicts.")
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
		file.Close()
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
	} else if mainCommand == "edit" {
		// Confirm decision, because this will write some decrypted data to disk
		fmt.Print("This will write the unencrypted value to disk. Proceed? [y/N] ")
		r := bufio.NewReader(os.Stdin)
		inp, err := r.ReadString('\n')
		if err != nil {
			log.Fatal(err)
		}
		inp = strings.Trim(inp, "\n")
		if !((strings.ToUpper(inp) == "Y") || (strings.ToUpper(inp) == "YES")) {
			// If not yes, just exit
			fmt.Println("Exiting")
			return
		}
		// Read the database
		dataKey := os.Args[2]
		content := readDb()
		dbData := unmarshalDb(content)
		decryptedData := make(map[string]string)
		for k, v := range dbData {
			decryptedKey := decrypt(k, key)
			decryptedValue := decrypt(v, key)
			decryptedData[decryptedKey] = decryptedValue
		}
		// Fetch the value in question
		dataValue := decryptedData[dataKey]
		// Prepare a temporary file
		randomBytes := make([]byte, 16)
		_, err = rand.Read(randomBytes)
		if err != nil {
			log.Fatal(err)
		}
		randomString := hex.EncodeToString(randomBytes)
		tmpFileName := fmt.Sprintf("%v.keyval", randomString)
		userHomeDir, err := os.UserHomeDir()
		if err != nil {
			log.Fatal(err)
		}
		tmpFilePath := filepath.Join(userHomeDir, dotfolder, tmpFileName)
		err = os.WriteFile(tmpFilePath, []byte(dataValue), 0o600)
		if err != nil {
			os.Remove(tmpFilePath)
			log.Fatal(err)
		}
		// Check if there's an EDITOR envvar
		editor := os.Getenv("EDITOR")
		if editor == "" {
			editor = "vi"
		}
		// Open the temporary file in the editor
		tty, err := os.OpenFile(ttyFd, os.O_RDWR, 0)
		if err != nil {
			os.Remove(tmpFilePath)
			log.Fatal(err)
		}
		defer tty.Close()
		cmd := exec.Command(editor, tmpFilePath)
		cmd.Stdin = tty
		cmd.Stdout = tty
		cmd.Stderr = tty
		err = cmd.Run()
		if err != nil {
			os.Remove(tmpFilePath)
			log.Fatal(err)
		}
		// Read the contents of the temporary file and delete it
		b, err := os.ReadFile(tmpFilePath)
		if err != nil {
			os.Remove(tmpFilePath)
			log.Fatal(err)
		}
		newValue := string(b)
		os.Remove(tmpFilePath)
		// Save the new data
		decryptedData[dataKey] = newValue
		encryptedData := make(map[string]string)
		for k, v := range decryptedData {
			encryptedKey := encrypt(k, key)
			encryptedValue := encrypt(v, key)
			encryptedData[encryptedKey] = encryptedValue
		}
		content = marshalDb(encryptedData)
		writeDb(content)
	} else if mainCommand == "dump" {
		if len(os.Args) == 2 {
			// To stdout
			dbData := readDb()
			fmt.Println(dbData)
		} else if len(os.Args) == 3 {
			// To a file
			dbData := readDb()
			filePath := os.Args[2]
			err := os.WriteFile(filePath, []byte(dbData), 0644)
			if err != nil {
				log.Fatal(err)
			}
		}
	} else if mainCommand == "restore" {
		// Confirm decision
		fmt.Print("This will overwrite your existing database. Proceed [y/N]? ")
		r := bufio.NewReader(os.Stdin)
		inp, err := r.ReadString('\n')
		if err != nil {
			log.Fatal(err)
		}
		inp = strings.Trim(inp, "\n")
		if !((strings.ToUpper(inp) == "Y") || (strings.ToUpper(inp) == "YES")) {
			// If not yes, just exit
			fmt.Println("Exiting")
			return
		}
		// From a file
		filePath := os.Args[2]
		dataBytes, err := os.ReadFile(filePath)
		if err != nil {
			log.Fatal(err)
		}
		data := string(dataBytes)
		writeDb(data)
	} else if mainCommand == "export-decrypt" {
		// Confirm decision
		fmt.Print("This will decrypt your data. Proceed [y/N]? ")
		r := bufio.NewReader(os.Stdin)
		inp, err := r.ReadString('\n')
		if err != nil {
			log.Fatal(err)
		}
		inp = strings.Trim(inp, "\n")
		if !((strings.ToUpper(inp) == "Y") || (strings.ToUpper(inp) == "YES")) {
			// If not yes, just exit
			fmt.Println("Exiting")
			return
		}
		content := readDb()
		dbData := unmarshalDb(content)
		decryptedData := make(map[string]string)
		for k, v := range dbData {
			decryptedKey := decrypt(k, key)
			decryptedValue := decrypt(v, key)
			decryptedData[decryptedKey] = decryptedValue
		}
		marshaledDecryptedData := marshalDb(decryptedData)
		filePath := os.Args[2]
		err = os.WriteFile(filePath, []byte(marshaledDecryptedData), 0744)
		if err != nil {
			log.Fatal(err)
		}
	} else if mainCommand == "import-encrypt" {
		// Confirm decision
		fmt.Print("This will overwrite your current database. Proceed [y/N]? ")
		r := bufio.NewReader(os.Stdin)
		inp, err := r.ReadString('\n')
		if err != nil {
			log.Fatal(err)
		}
		inp = strings.Trim(inp, "\n")
		if !((strings.ToUpper(inp) == "Y") || (strings.ToUpper(inp) == "YES")) {
			// If not yes, just exit
			fmt.Println("Exiting")
			return
		}
		filePath := os.Args[2]
		dataBytes, err := os.ReadFile(filePath)
		if err != nil {
			log.Fatal(err)
		}
		data := string(dataBytes)
		decryptedData := unmarshalDb(data)
		encryptedData := make(map[string]string)
		for k, v := range decryptedData {
			encryptedKey := encrypt(k, key)
			encryptedValue := encrypt(v, key)
			encryptedData[encryptedKey] = encryptedValue
		}
		marshaledEncryptedData := marshalDb(encryptedData)
		writeDb(marshaledEncryptedData)
	} else if mainCommand == "merge" {
		file1Path := os.Args[2]
		file2Path := os.Args[3]
		outputFilePath := os.Args[4]
		fmt.Printf("Merging %v and %v into %v\n", file1Path, file2Path, outputFilePath)
		// Read file 1
		file1Bytes, err := os.ReadFile(file1Path)
		if err != nil {
			log.Fatal(err)
		}
		file1Data := string(file1Bytes)
		unmarshaledFile1Data := unmarshalDb(file1Data)
		decryptedFile1Data := make(map[string]string)
		for k, v := range unmarshaledFile1Data {
			decryptedKey := decrypt(k, key)
			decryptedValue := decrypt(v, key)
			decryptedFile1Data[decryptedKey] = decryptedValue
		}
		// Read file 2
		file2Bytes, err := os.ReadFile(file2Path)
		if err != nil {
			log.Fatal(err)
		}
		file2Data := string(file2Bytes)
		unmarshaledFile2Data := unmarshalDb(file2Data)
		decryptedFile2Data := make(map[string]string)
		for k, v := range unmarshaledFile2Data {
			decryptedKey := decrypt(k, key)
			decryptedValue := decrypt(v, key)
			decryptedFile2Data[decryptedKey] = decryptedValue
		}
		// Get all the keys used across both file 1 and file 2
		var allKeys []string
		for k, _ := range decryptedFile1Data {
			allKeys = append(allKeys, k)
		}
		for k, _ := range decryptedFile2Data {
			allKeys = append(allKeys, k)
		}
		keysMap := make(map[string]bool)
		for _, k := range allKeys {
			keysMap[k] = true
		}
		var keysUnion []string
		for k, _ := range keysMap {
			keysUnion = append(keysUnion, k)
		}
		// Handle merge
		mergedData := make(map[string]string)
		for _, k := range keysUnion {
			// fmt.Println("Handling", k)
			value1 := decryptedFile1Data[k]
			value2 := decryptedFile2Data[k]
			// fmt.Println(value1)
			// fmt.Println(value2)
			if value1 == value2 {
				mergedData[k] = value1
			} else if (value1 == "") || (value2 == "") {
				if value1 == "" {
					mergedData[k] = value2
				} else if value2 == "" {
					mergedData[k] = value1
				}
			} else if value1 != value2 {
				fmt.Println("=== !!! ===")
				fmt.Printf("Values for %v in (1) %v and (2) %v do not match.\n", k, file1Path, file2Path)
				// Get value 1 display
				value1Length := len(value1)
				var value1Display string
				if value1Length >= 80 {
					value1Display = value1[:80]
				} else {
					value1Display = value1
				}
				// Get value 2 display
				value2Length := len(value2)
				var value2Display string
				if value2Length >= 80 {
					value2Display = value2[:80]
				} else {
					value2Display = value2
				}
				fmt.Printf("(1) %v value is: %v\n", file1Path, value1Display)
				fmt.Printf("(2) %v value is: %v\n", file2Path, value2Display)
				fmt.Print("Which to retain [1/2]? (1) ")
				r := bufio.NewReader(os.Stdin)
				inp, err := r.ReadString('\n')
				if err != nil {
					log.Fatal(err)
				}
				inp = strings.Trim(inp, "\n")
				if (inp == "") || (inp == "1") {
					fmt.Printf("Retaining %v\n", value1Display)
					mergedData[k] = value1
				} else if inp == "2" {
					fmt.Printf("Retaining %v\n", value2Display)
					mergedData[k] = value2
				}
			}
		}
		// Encrypt the merged data
		encryptedMergedData := make(map[string]string)
		for k, v := range mergedData {
			encryptedKey := encrypt(k, key)
			encryptedValue := encrypt(v, key)
			encryptedMergedData[encryptedKey] = encryptedValue
		}
		marshaledEncryptedData := marshalDb(encryptedMergedData)
		fmt.Printf("Writing merged data to %v\n", outputFilePath)
		err = os.WriteFile(outputFilePath, []byte(marshaledEncryptedData), 0644)
		if err != nil {
			log.Fatal(err)
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
