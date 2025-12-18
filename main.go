package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/crypto/scrypt"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Url               string   `yaml:"url"`
	InsecureTls       bool     `yaml:"insecure_tls"`
	HttpTimeoutSec    int      `yaml:"http_timeout_sec"`
	AuthHeader        string   `yaml:"auth_header"`
	AuthToken         string   `yaml:"auth_token"`
	HttpMethod        string   `yaml:"http_method"`
	PayloadPassword   string   `yaml:"payload_password"`
	UnlockCmd         string   `yaml:"unlock_cmd"`
	UnlockArgs        []string `yaml:"unlock_args"`
	UnlockPlaceholder string   `yaml:"unlock_placeholder"`
}

var ErrHttpPageExpired = errors.New("419: page expired")
var Conf Config

func loadConfig(configPath string) {
	yamlFile, err := os.ReadFile(configPath)
	if err != nil {
		log.Fatalf("yamlFile.Get err   #%v ", err)
	}

	err = yaml.Unmarshal(yamlFile, &Conf)
	if err != nil {
		log.Fatalf("Unmarshal: %v", err)
	}
}

func httpRequest(method string, url string, authHeader string, token string) (string, error) {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set(authHeader, token)
	req.Header.Set("User-Agent", "NucUnlocker 1.0")

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: Conf.InsecureTls},
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(Conf.HttpTimeoutSec) * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	if resp.StatusCode == 419 {
		return "", ErrHttpPageExpired
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP status code: %d", resp.StatusCode)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// copy pasted from https://bruinsslot.jp/post/golang-crypto/
func Encrypt(key, data []byte) ([]byte, error) {
	if len(key) < 10 {
		return nil, fmt.Errorf("key must be at least 10 characters")
	}

	if len(data) == 0 {
		return nil, fmt.Errorf("data must not be empty")
	}

	key, salt, err := DeriveKey(key, nil)
	if err != nil {
		return nil, err
	}

	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)

	ciphertext = append(ciphertext, salt...)

	return ciphertext, nil
}

func Decrypt(key, data []byte) ([]byte, error) {
	if len(data) < 64 {
		return nil, fmt.Errorf("data must must be at least 64 characters long")
	}
	salt, data := data[len(data)-32:], data[:len(data)-32]

	key, _, err := DeriveKey(key, salt)
	if err != nil {
		return nil, err
	}

	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, err
	}

	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func DeriveKey(password, salt []byte) ([]byte, []byte, error) {
	if salt == nil {
		salt = make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			return nil, nil, err
		}
	}

	key, err := scrypt.Key(password, salt, 16384, 8, 1, 32)
	if err != nil {
		return nil, nil, err
	}

	return key, salt, nil
}

func main() {
	usage := `
Usage: call with --help to see available arguments
Use encrypt/decrypt mode to create the payload
see the repo nucunlocker.yml for the config format
	`
	// Parse command line arguments
	configPath := flag.String("c", "nucunlocker.yml", "path to config file")
	mode := flag.String("m", "", "run mode (unlock/encrypt/decrypt)")
	data := flag.String("d", "", "data to encrypt/decrypt")
	password := flag.String("p", "", "password to encrypt/decrypt (for encrypt/decrypt mode)")
	retry := flag.Bool("r", false, "retry on http 419 error indefinitely")

	flag.Parse()
	switch *mode {
	case "unlock": // default mode
		log.Println("Unlocking NUC 🤖")
		loadConfig(*configPath)
		// make api call
		var response string
		var err error
		for {
			response, err = httpRequest(Conf.HttpMethod, Conf.Url, Conf.AuthHeader, Conf.AuthToken)
			if err != nil {
				if err == ErrHttpPageExpired && *retry {
					log.Printf("Warning: %v, retry enabled ...", err)
					time.Sleep(3 * time.Second)
					continue
				} else {
					log.Fatalf("Error: %v", err)
				}
			} else {
				break
			}
		}
		log.Println("Payload fetched ✅")

		// decrypt response
		ciphertextbyte, err := base64.StdEncoding.DecodeString(response)
		if err != nil {
			log.Fatal(err)
		}
		plaintextbyte, err := Decrypt([]byte(Conf.PayloadPassword), ciphertextbyte)
		if err != nil {
			log.Fatal(err)
		}
		secret := string(plaintextbyte)
		log.Println("Payload decrypted ✅")

		// execute output command
		updatedArgs := make([]string, len(Conf.UnlockArgs))
		copy(updatedArgs, Conf.UnlockArgs)
		for i, arg := range updatedArgs {
			updatedArgs[i] = strings.ReplaceAll(arg, Conf.UnlockPlaceholder, secret)
		}
		log.Println("Command prepared ✅")
		cmd := exec.Command(Conf.UnlockCmd, updatedArgs...)
		cmd.Env = os.Environ()
		output, errr := cmd.CombinedOutput()
		if errr != nil {
			log.Fatalf("Error: %v, output: %s", errr, output)
		}
		fmt.Printf("Command output: \n%s\n", output)
		log.Println("NUC unlocked ✅")

	case "encrypt":
		// Helper to create encrypted payload (small payload as it fit in argument lines)
		fmt.Println("Encrypting clear text")
		if len(*password) < 1 {
			log.Fatal("Password len can't be zero")
		}
		ciphertextbyte, err := Encrypt([]byte(*password), []byte(*data))
		if err != nil {
			log.Fatal(err)
		}
		base64ciphertext := base64.StdEncoding.EncodeToString(ciphertextbyte)
		fmt.Printf("Encrypted data: \n----COPY FROM HERE----\n%s\n-----COPY TO HERE-----\n", string(base64ciphertext))
	case "decrypt":
		// Helper to verify your payload
		fmt.Println("Decrypting cipher text")
		if len(*password) < 1 {
			log.Fatal("Password len can't be zero")
		}
		ciphertextbyte, err := base64.StdEncoding.DecodeString(*data)
		if err != nil {
			log.Fatal(err)
		}
		plaintext, err := Decrypt([]byte(*password), ciphertextbyte)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Decrypted data: \n----COPY FROM HERE----\n%s\n-----COPY TO HERE-----\n", string(plaintext))
	default:
		fmt.Println(usage)
		log.Fatalf("Invalid mode")
		os.Exit(1)
	}
}
