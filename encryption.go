package bestbuy_encryption

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	b64 "encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

func (e *Encryption) EncryptLogin() (EncryptedLogin, error) {
	encryptedEmail, err := e.encryptEmail(e.Email)
	if err != nil {
		return EncryptedLogin{}, err
	}

	encryptedActivity, err := e.encryptUserActivity(
		fmt.Sprintf(
			"{\"mouseMoved\":true,\"keyboardUsed\":true,\"fieldReceivedInput\":true,\"fieldReceivedFocus\":true,\"timestamp\":\"%s\",\"email\":\"%s\"}",
			time.Now().UTC().Format("2006-01-02T15:04:05.999Z07:00"),
			e.Email,
		),
	)
	if err != nil {
		return EncryptedLogin{}, err
	}

	encryptedUserAgent, err := e.encryptUserActivity(
		fmt.Sprintf(
			"{\"userAgent\":\"%s\"}",
			e.UserAgent,
		),
	)
	if err != nil {
		return EncryptedLogin{}, err
	}

	return EncryptedLogin{
		EncryptedEmail:        encryptedEmail,
		EncryptedUserActivity: encryptedActivity,
		EncryptedUserAgent:    encryptedUserAgent,
	}, nil
}

func (e *Encryption) getCSIData(keyClass string) (CSIData, error) {
	request, requestError := http.NewRequest("GET", fmt.Sprintf("https://www.bestbuy.com/api/csiservice/v2/key/%s", keyClass), nil)
	if requestError != nil {
		return CSIData{}, requestError
	}

	request.Header = http.Header{
		"pragma":             {"no-cache"},
		"cache-control":      {"no-cache"},
		"sec-ch-ua":          {""},
		"dnt":                {"1"},
		"sec-ch-ua-mobile":   {"?0"},
		"user-agent":         {e.UserAgent},
		"sec-ch-ua-platform": {""},
		"content-type":       {"application/json"},
		"accept":             {"*/*"},
		"sec-fetch-site":     {"same-origin"},
		"sec-fetch-mode":     {"cors"},
		"sec-fetch-dest":     {"empty"},
		"referer":            {"https://www.bestbuy.com/identity/signin"},
		"accept-encoding":    {"gzip, deflate, br"},
		"accept-language":    {"en-US,en;q=0.9"},
	}

	response, responseError := e.Client.Do(request)
	if responseError != nil {
		return CSIData{}, responseError
	}
	defer response.Body.Close()

	body, bodyError := ioutil.ReadAll(response.Body)
	if bodyError != nil {
		return CSIData{}, bodyError
	}

	var csiData CSIData
	err := json.Unmarshal(body, &csiData)
	if err != nil {
		return CSIData{}, err
	}

	return csiData, nil
}

func (e *Encryption) encryptUserActivity(userActivity string) (string, error) {
	csiData, err := e.getCSIData("cia-user-activity")
	if err != nil {
		return "", err
	}

	return e.encrypt(userActivity, csiData, true), nil
}

func (e *Encryption) encryptEmail(email string) (string, error) {
	csiData, err := e.getCSIData("cia-email")
	if err != nil {
		fmt.Println("[ERROR] unable to get CSIData:", err)
		return "", err
	}

	return e.encrypt(email, csiData, true), nil
}

func (e *Encryption) EncryptCard(cardNumber string) (string, error) {
	csiData, err := e.getCSIData("tas")
	if err != nil {
		return "", err
	}

	data := fmt.Sprintf("00960001%s", cardNumber)

	encrypted := e.encryptPayment(cardNumber, data, csiData)
	if encrypted == nil {
		return "", errors.New("failed to encrypt payment method")
	}

	return *encrypted, nil
}

func (e *Encryption) encryptPayment(cardNumber, payload string, data CSIData) *string {
	rsaKey := getPublicKey(data)
	if rsaKey == nil {
		return nil
	}
	data.RsaPublicKey = rsaKey

	ciphertext := encryptPayload(payload, data, true)

	n := len(cardNumber)
	v := fmt.Sprintf(
		"%s:3:%s:%s",
		ciphertext,
		data.KeyID,
		cardNumber[0:6]+strings.Repeat("0", n-9)+cardNumber[n-4:],
	)

	return &v
}

func (e *Encryption) encrypt(payload string, data CSIData, useSha1 bool) string {
	rsaKey := getPublicKey(data)
	if rsaKey == nil {
		fmt.Println("[ERROR] unable to parse public key!")
		return ""
	}
	data.RsaPublicKey = rsaKey

	ciphertext := encryptPayload(payload, data, useSha1)

	return fmt.Sprintf("1:%s:%s", data.KeyID, ciphertext)
}

// RSA Encryption

func encryptPayload(payload string, data CSIData, useSha1 bool) string {
	if data.RsaPublicKey == nil {
		fmt.Println("[ERROR] -> unable to get rsa public key")
		return ""
	}
	hash := sha256.New()
	if useSha1 {
		hash = sha1.New()
	}
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, data.RsaPublicKey, []byte(payload), nil)
	if err != nil {
		fmt.Println("[ERROR] -> unable to decrypt encoded public key: ", err)
		return ""
	}

	return b64.StdEncoding.EncodeToString(ciphertext)
}

func getPublicKey(data CSIData) *rsa.PublicKey {
	removeBegin := strings.ReplaceAll(data.PublicKey, "-----BEGIN PUBLIC KEY-----", "")
	removeEnd := strings.ReplaceAll(removeBegin, "-----END PUBLIC KEY-----", "")
	removeWhitespace := strings.TrimSpace(removeEnd)

	block, _ := pem.Decode([]byte(`
-----BEGIN PUBLIC KEY-----
` + removeWhitespace + `
-----END PUBLIC KEY-----`))
	if block == nil {
		fmt.Println("[ERROR] -> unable to parse PEM block containing the public key")
		return nil
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		fmt.Println("[ERROR] -> unable to parse DER encoded public key")
		return nil
	}

	rsaPublickey, _ := pub.(*rsa.PublicKey)
	return rsaPublickey
}
