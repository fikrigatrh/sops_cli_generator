package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "sopscli",
		Short: "🔐 SOPS Secret Manager",
		Run: func(cmd *cobra.Command, args []string) {
			for {
				fmt.Println("\n🔐 SOPS Secret Manager")
				fmt.Println(strings.Repeat("=", 22))
				fmt.Println("1. Create new secret file")
				fmt.Println("2. Edit existing secret file")
				fmt.Println("3. View encrypted file (decrypt to view)")
				fmt.Println("4. Encrypt existing YAML file")
				fmt.Println("5. Decrypt file")
				fmt.Println("6. Manage Age keys")
				fmt.Println("7. List secret files")
				fmt.Println("8. Exit")
				fmt.Print("\nSelect option (1-8): ")

				scanner := bufio.NewScanner(os.Stdin)
				scanner.Scan()
				choice := scanner.Text()

				switch choice {
				case "1":
					createSecretFile()
				case "2":
					editSecretFile()
				case "3":
					viewDecryptedFile()
				case "4":
					encryptYAMLFile()
				case "5":
					decryptFile()
				case "6":
					manageAgeKeys()
				case "7":
					listSecretFiles()
				case "8":
					fmt.Println("Exiting...")
					os.Exit(0)
				default:
					fmt.Println("Invalid option")
				}
			}
		},
	}

	viper.AutomaticEnv()
	if err := rootCmd.Execute(); err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
}

func createSecretFile() {
	scanner := bufio.NewScanner(os.Stdin)

	fmt.Print("Enter name for the new secret file (e.g., secrets.yaml): ")
	scanner.Scan()
	filename := scanner.Text()

	if filename == "" {
		fmt.Println("Filename cannot be empty.")
		return
	}

	secrets := make(map[string]string)

	for {
		fmt.Print("Enter key (or leave empty to finish): ")
		scanner.Scan()
		key := scanner.Text()
		if key == "" {
			break
		}

		fmt.Print("Enter value: ")
		scanner.Scan()
		value := scanner.Text()

		secrets[key] = value
	}

	out, err := yaml.Marshal(secrets)
	if err != nil {
		fmt.Println("Error encoding YAML:", err)
		return
	}

	err = os.WriteFile(filename, out, 0644)
	if err != nil {
		fmt.Println("Error writing file:", err)
		return
	}

	fmt.Println("Secret file created:", filename)
}

func editSecretFile() {
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Print("Enter the name of the YAML secret file to edit: ")
	scanner.Scan()
	filename := scanner.Text()

	data, err := os.ReadFile(filename)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}

	var secrets map[string]string
	err = yaml.Unmarshal(data, &secrets)
	if err != nil {
		fmt.Println("Error parsing YAML:", err)
		return
	}

	for {
		fmt.Print("Enter key to edit (or leave empty to finish): ")
		scanner.Scan()
		key := strings.TrimSpace(scanner.Text())
		if key == "" {
			break
		}

		if current, ok := secrets[key]; ok {
			fmt.Printf("Current value: %s\n", current)
		} else {
			fmt.Println("Key not found. It will be added.")
		}

		fmt.Print("Enter new value: ")
		scanner.Scan()
		newValue := scanner.Text()
		secrets[key] = newValue
	}

	out, err := yaml.Marshal(secrets)
	if err != nil {
		fmt.Println("Error encoding YAML:", err)
		return
	}

	err = os.WriteFile(filename, out, 0644)
	if err != nil {
		fmt.Println("Error writing file:", err)
		return
	}

	fmt.Println("Secret file updated:", filename)
}

func viewDecryptedFile() {
	scanner := bufio.NewScanner(os.Stdin)

	fmt.Print("Input encrypted YAML file: ")
	scanner.Scan()
	inFile := scanner.Text()

	identity := getAgeIdentityKey()
	if identity == "" {
		fmt.Print("Age identity key: ")
		scanner.Scan()
		identity = scanner.Text()
		if identity == "" {
			fmt.Println("Identity key cannot be empty.")
			return
		}
	}

	tempFile := "temp_decrypted.yaml"
	err := DecryptSelectedFields(inFile, tempFile, identity)
	if err != nil {
		fmt.Println("Error decrypting file:", err)
		return
	}

	decryptedData, err := os.ReadFile(tempFile)
	if err != nil {
		fmt.Println("Error reading decrypted file:", err)
		return
	}

	fmt.Println("\nDecrypted Content:\n")
	fmt.Println(string(decryptedData))

	_ = os.Remove(tempFile) // Clean up
}

func encryptYAMLFile() {
	scanner := bufio.NewScanner(os.Stdin)

	fmt.Print("Input path to YAML file: ")
	scanner.Scan()
	inFile := strings.TrimSpace(scanner.Text())

	if inFile == "" {
		fmt.Println("File path cannot be empty.")
		return
	}

	if _, err := os.Stat(inFile); os.IsNotExist(err) {
		fmt.Printf("File does not exist: %s\n", inFile)
		return
	}

	ext := filepath.Ext(inFile)
	base := strings.TrimSuffix(inFile, ext)
	outFile := base + ".enc" + ext

	recipient := getAgeRecipientKey()
	if recipient == "" {
		fmt.Print("Age recipient key: ")
		scanner.Scan()
		recipient = strings.TrimSpace(scanner.Text())
		if recipient == "" {
			fmt.Println("Recipient key cannot be empty.")
			return
		}
	}

	fmt.Println("\nAnalyzing YAML file...")
	fields, err := getYAMLFields(inFile)
	if err != nil {
		fmt.Printf("Error reading YAML file: %v\n", err)
		return
	}

	if len(fields) == 0 {
		fmt.Println("No fields found in YAML file.")
		return
	}

	fmt.Printf("Available fields in %s:\n", inFile)
	for i, field := range fields {
		fmt.Printf("  %d. %s\n", i+1, field)
	}

	fmt.Print("\nFields to EXCLUDE from encryption (comma-separated, or leave empty to encrypt all): ")
	scanner.Scan()
	excludeInput := strings.TrimSpace(scanner.Text())

	var excludeFields []string
	if excludeInput != "" {
		excludeFields = strings.Split(excludeInput, ",")
		for i := range excludeFields {
			excludeFields[i] = strings.TrimSpace(excludeFields[i])
		}
	}

	var encryptFields []string
	for _, field := range fields {
		shouldExclude := false
		for _, exclude := range excludeFields {
			if field == exclude {
				shouldExclude = true
				break
			}
		}
		if !shouldExclude {
			encryptFields = append(encryptFields, field)
		}
	}

	if len(encryptFields) == 0 {
		fmt.Println("No fields selected for encryption.")
		return
	}

	fmt.Printf("Fields to be encrypted: %s\n", strings.Join(encryptFields, ", "))
	fmt.Printf("Output file: %s\n", outFile)

	err = EncryptSelectedFields(inFile, outFile, recipient, encryptFields)
	if err != nil {
		fmt.Println("Error encrypting file:", err)
		return
	}

	fmt.Printf("✅ Encryption completed successfully!\n")
	fmt.Printf("📁 Encrypted file saved as: %s\n", outFile)
}

func decryptFile() {
	scanner := bufio.NewScanner(os.Stdin)

	fmt.Print("Input path to encrypted YAML file: ")
	scanner.Scan()
	inFile := strings.TrimSpace(scanner.Text())

	if inFile == "" {
		fmt.Println("File path cannot be empty.")
		return
	}

	if _, err := os.Stat(inFile); os.IsNotExist(err) {
		fmt.Printf("File does not exist: %s\n", inFile)
		return
	}

	var outFile string
	if strings.Contains(inFile, ".enc.") {
		outFile = strings.Replace(inFile, ".enc.", ".", 1)
	} else if strings.HasSuffix(inFile, ".enc") {
		outFile = strings.TrimSuffix(inFile, ".enc")
	} else {
		ext := filepath.Ext(inFile)
		base := strings.TrimSuffix(inFile, ext)
		outFile = base + ".dec" + ext
	}

	identity := getAgeIdentityKey()
	if identity == "" {
		fmt.Print("Age identity key: ")
		scanner.Scan()
		identity = strings.TrimSpace(scanner.Text())
		if identity == "" {
			fmt.Println("Identity key cannot be empty.")
			return
		}
	}

	fmt.Printf("Decrypting %s to %s...\n", inFile, outFile)

	err := DecryptSelectedFields(inFile, outFile, identity)
	if err != nil {
		fmt.Println("Error decrypting file:", err)
		return
	}

	fmt.Printf("✅ Decryption completed successfully!\n")
	fmt.Printf("📁 Decrypted file saved as: %s\n", outFile)
}

func manageAgeKeys() {
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Println("\nManage Age Keys")
	fmt.Println("1. Generate new key pair")
	fmt.Println("2. Show existing key file")
	fmt.Print("Choose option (1-2): ")
	scanner.Scan()
	choice := scanner.Text()

	switch choice {
	case "1":
		key, err := age.GenerateX25519Identity()
		if err != nil {
			fmt.Println("Failed to generate key:", err)
			return
		}
		file, err := os.Create("age-keys.txt")
		if err != nil {
			fmt.Println("Error saving key file:", err)
			return
		}
		defer file.Close()
		file.WriteString("# Private key (identity)\n")
		file.WriteString(key.String() + "\n")
		file.WriteString("\n# Public key (recipient)\n")
		file.WriteString(key.Recipient().String() + "\n")
		fmt.Println("Key pair saved to age-keys.txt")
	case "2":
		data, err := os.ReadFile("age-keys.txt")
		if err != nil {
			fmt.Println("Error reading key file:", err)
			return
		}
		fmt.Println("\n" + string(data))
	default:
		fmt.Println("Invalid option")
	}
}

type FileInfo struct {
	Name        string
	Path        string
	Size        int64
	ModTime     time.Time
	IsEncrypted bool
}

func listSecretFiles() {
	fmt.Println("\n📁 Secret Files")
	fmt.Println(strings.Repeat("=", 50))

	currentDir, err := os.Getwd()
	if err != nil {
		fmt.Println("Error getting current directory:", err)
		return
	}

	var files []FileInfo

	err = filepath.Walk(currentDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if info.IsDir() || strings.HasPrefix(info.Name(), ".") {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(info.Name()))
		if ext == ".yaml" || ext == ".yml" {
			isEncrypted := false
			if strings.Contains(info.Name(), ".enc.") ||
				strings.HasSuffix(strings.ToLower(info.Name()), ".enc.yaml") ||
				strings.HasSuffix(strings.ToLower(info.Name()), ".enc.yml") {
				isEncrypted = true
			} else if hasEncryptedContent(path) {
				isEncrypted = true
			}

			relPath, _ := filepath.Rel(currentDir, path)
			files = append(files, FileInfo{
				Name:        info.Name(),
				Path:        relPath,
				Size:        info.Size(),
				ModTime:     info.ModTime(),
				IsEncrypted: isEncrypted,
			})
		}
		return nil
	})

	if err != nil {
		fmt.Println("Error scanning directory:", err)
		return
	}

	if len(files) == 0 {
		fmt.Println("No YAML secret files found in current directory.")
		return
	}

	sort.Slice(files, func(i, j int) bool {
		return files[i].ModTime.After(files[j].ModTime)
	})

	fmt.Printf("Found %d YAML file(s):\n\n", len(files))

	for i, file := range files {
		status := "🔓 Plain"
		if file.IsEncrypted {
			status = "🔐 Encrypted"
		}

		fmt.Printf("%d. %s\n", i+1, file.Name)
		fmt.Printf("   📍 Path: %s\n", file.Path)
		fmt.Printf("   📊 Size: %s\n", formatFileSize(file.Size))
		fmt.Printf("   📅 Modified: %s\n", file.ModTime.Format("2006-01-02 15:04:05"))
		fmt.Printf("   %s\n", status)

		if !file.IsEncrypted {
			if fields, err := getYAMLFields(file.Path); err == nil && len(fields) > 0 {
				fmt.Printf("   🔑 Fields: %s\n", strings.Join(fields, ", "))
			}
		}
		fmt.Println()
	}

	encryptedCount := 0
	plainCount := 0
	for _, file := range files {
		if file.IsEncrypted {
			encryptedCount++
		} else {
			plainCount++
		}
	}

	fmt.Println(strings.Repeat("-", 50))
	fmt.Printf("📈 Summary: %d encrypted, %d plain text\n", encryptedCount, plainCount)

	if plainCount > 0 {
		fmt.Printf("⚠️  Warning: %d unencrypted secret file(s) found!\n", plainCount)
	}
}

func hasEncryptedContent(filename string) bool {
	data, err := os.ReadFile(filename)
	if err != nil {
		return false
	}

	content := string(data)
	return strings.Contains(content, "-----BEGIN AGE ENCRYPTED FILE-----") ||
		strings.Contains(content, "age1") ||
		strings.Contains(content, "ENC[")
}

func formatFileSize(size int64) string {
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(size)/float64(div), "KMGTPE"[exp])
}

func getYAMLFields(filename string) ([]string, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var yamlData map[string]interface{}
	err = yaml.Unmarshal(data, &yamlData)
	if err != nil {
		return nil, err
	}

	var fields []string
	extractFields(yamlData, "", &fields)

	sort.Strings(fields)
	return fields, nil
}

func extractFields(data interface{}, prefix string, fields *[]string) {
	switch v := data.(type) {
	case map[string]interface{}:
		for key, value := range v {
			fullKey := key
			if prefix != "" {
				fullKey = prefix + "." + key
			}
			*fields = append(*fields, fullKey)
			extractFields(value, fullKey, fields)
		}
	case []interface{}:
		// Arrays are not processed for fields
	}
}

func getAgeRecipientKey() string {
	data, err := os.ReadFile("age-keys.txt")
	if err != nil {
		return ""
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") && strings.HasPrefix(line, "age1") && len(line) > 50 {
			return line
		}
	}
	return ""
}

func getAgeIdentityKey() string {
	data, err := os.ReadFile("age-keys.txt")
	if err != nil {
		return ""
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") && strings.HasPrefix(line, "AGE-SECRET-KEY-") {
			return line
		}
	}
	return ""
}

func EncryptSelectedFields(inputFile, outputFile, recipientKey string, fieldsToEncrypt []string) error {
	data, err := os.ReadFile(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	var yamlData map[string]interface{}
	err = yaml.Unmarshal(data, &yamlData)
	if err != nil {
		return fmt.Errorf("failed to parse YAML: %w", err)
	}

	recipient, err := age.ParseX25519Recipient(recipientKey)
	if err != nil {
		return fmt.Errorf("failed to parse recipient key: %w", err)
	}

	// Create set for quick lookup
	encryptSet := make(map[string]bool)
	for _, field := range fieldsToEncrypt {
		encryptSet[field] = true
	}

	// Encrypt fields recursively
	if err := encryptFieldsRecursive(yamlData, "", encryptSet, recipient); err != nil {
		return err
	}

	file, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	encoder := yaml.NewEncoder(file)
	encoder.SetIndent(2)
	if err := encoder.Encode(yamlData); err != nil {
		return fmt.Errorf("failed to encode YAML: %w", err)
	}

	return nil
}

func encryptFieldsRecursive(data interface{}, currentPath string, encryptSet map[string]bool, recipient *age.X25519Recipient) error {
	switch v := data.(type) {
	case map[string]interface{}:
		for key, value := range v {
			newPath := key
			if currentPath != "" {
				newPath = currentPath + "." + key
			}

			// Check if this field should be encrypted
			shouldEncrypt := encryptSet[newPath]

			if shouldEncrypt {
				// Handle leaf values immediately
				if isScalar(value) {
					encrypted, err := encryptString(value, recipient)
					if err != nil {
						return fmt.Errorf("failed to encrypt field '%s': %w", newPath, err)
					}
					v[key] = fmt.Sprintf("ENC[%s]", encrypted)
				} else {
					// Recurse into nested structures
					if err := encryptFieldsRecursive(value, newPath, encryptSet, recipient); err != nil {
						return err
					}
				}
			} else {
				// Continue recursion even if parent isn't directly selected
				if err := encryptFieldsRecursive(value, newPath, encryptSet, recipient); err != nil {
					return err
				}
			}
		}
	case []interface{}:
		// Handle array elements
		for i, item := range v {
			if isScalar(item) && encryptSet[currentPath] {
				encrypted, err := encryptString(item, recipient)
				if err != nil {
					return fmt.Errorf("failed to encrypt array element at '%s[%d]': %w", currentPath, i, err)
				}
				v[i] = fmt.Sprintf("ENC[%s]", encrypted)
			} else {
				// Recurse into array elements
				if err := encryptFieldsRecursive(item, currentPath, encryptSet, recipient); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func isScalar(value interface{}) bool {
	switch value.(type) {
	case string, int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64,
		float32, float64, bool:
		return true
	default:
		return false
	}
}

func DecryptSelectedFields(inputFile, outputFile, identityKey string) error {
	data, err := os.ReadFile(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	var yamlData map[string]interface{}
	err = yaml.Unmarshal(data, &yamlData)
	if err != nil {
		return fmt.Errorf("failed to parse YAML: %w", err)
	}

	identity, err := age.ParseX25519Identity(identityKey)
	if err != nil {
		return fmt.Errorf("failed to parse identity key: %w", err)
	}

	err = decryptNestedFields(yamlData, identity)
	if err != nil {
		return fmt.Errorf("failed to decrypt fields: %w", err)
	}

	file, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	encoder := yaml.NewEncoder(file)
	encoder.SetIndent(2)
	err = encoder.Encode(yamlData)
	if err != nil {
		return fmt.Errorf("failed to encode YAML: %w", err)
	}

	return nil
}

func encryptString(value interface{}, recipient *age.X25519Recipient) (string, error) {
	// Convert any primitive to string
	plaintext := fmt.Sprintf("%v", value)

	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipient)
	if err != nil {
		return "", err
	}

	if _, err := io.WriteString(w, plaintext); err != nil {
		return "", err
	}

	if err := w.Close(); err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

func decryptString(ciphertext string, identity *age.X25519Identity) (interface{}, error) {
	ciphertext = strings.TrimSpace(ciphertext)

	decoded, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		decoded = []byte(ciphertext)
	}

	buf := bytes.NewReader(decoded)
	r, err := age.Decrypt(buf, identity)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	var result bytes.Buffer
	if _, err := io.Copy(&result, r); err != nil {
		return nil, fmt.Errorf("failed to read decrypted data: %w", err)
	}

	decryptedStr := result.String()

	var yamlNode yaml.Node
	if err := yaml.Unmarshal([]byte(decryptedStr), &yamlNode); err == nil && yamlNode.Kind != 0 {
		var value interface{}
		if err := yamlNode.Decode(&value); err != nil {
			return nil, fmt.Errorf("failed to decode YAML node: %w", err)
		}
		return value, nil
	}

	return decryptedStr, nil
}

func decryptNestedFields(data interface{}, identity *age.X25519Identity) error {
	switch v := data.(type) {
	case map[string]interface{}:
		for key, value := range v {
			// Handle string values
			if valueStr, ok := value.(string); ok {
				decrypted, err := tryDecryptString(valueStr, identity)
				if err == nil {
					v[key] = decrypted
					continue
				}
			}

			// Recursively process nested structures
			if err := decryptNestedFields(value, identity); err != nil {
				return err
			}
		}
	case []interface{}:
		for i, item := range v {
			// Handle encrypted array elements
			if itemStr, ok := item.(string); ok {
				decrypted, err := tryDecryptString(itemStr, identity)
				if err == nil {
					v[i] = decrypted
					continue
				}
			}

			// Recursively process nested structures in arrays
			if err := decryptNestedFields(item, identity); err != nil {
				return err
			}
		}
	}
	return nil
}

func tryDecryptString(value string, identity *age.X25519Identity) (interface{}, error) {
	trimmed := strings.TrimSpace(value)

	// Handle standard ENC[...] format
	if strings.HasPrefix(trimmed, "ENC[") && strings.HasSuffix(trimmed, "]") {
		return decryptString(trimmed[4:len(trimmed)-1], identity)
	}

	// Handle raw base64 strings
	if _, err := base64.StdEncoding.DecodeString(trimmed); err == nil {
		return decryptString(trimmed, identity)
	}

	// Not an encrypted string
	return nil, fmt.Errorf("not an encrypted value")
}
