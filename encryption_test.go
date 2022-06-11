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
		Client:    client,
	}

	encrypted, err := enc.EncryptLogin()
	if err != nil {
		t.Error(err)
	}

	fmt.Println(encrypted.EncryptedEmail)
	fmt.Println(encrypted.EncryptedUserAgent)
	fmt.Println(encrypted.EncryptedUserActivity)

	paymentMethod, err := enc.EncryptCard("4111111111111111")
	if err != nil {
		t.Error(err)
	}

	fmt.Println(paymentMethod)
}
