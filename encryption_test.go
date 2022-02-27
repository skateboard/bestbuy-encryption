package bestbuy_encryption

import (
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"testing"
)

func TestEncryption(t *testing.T) {
	jar, _ := cookiejar.New(nil)
	client := http.Client{Jar: jar}

	enc := Encryption{
		Email:     "test@gmail.com",
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36",
		Client:   	client,
	}

	encrypted, success := enc.EncryptLogin()
	if !success {
		t.Error("Failed to encrypt login")
	}

	fmt.Println(encrypted.EncryptedEmail)
	fmt.Println(encrypted.EncryptedUserActivity)
	fmt.Println(encrypted.EncryptedUserActivity)
}
