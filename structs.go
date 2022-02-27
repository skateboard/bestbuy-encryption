package bestbuy_encryption

import (
	"crypto/rsa"
	"net/http"
)

type Encryption struct {
	Email string
	UserAgent string

	Client http.Client
}

type CSIData struct {
	PublicKey string `json:"publicKey"`
	KeyID     string `json:"keyId"`

	RsaPublicKey *rsa.PublicKey `json:"-"`
}

type EncryptedLogin struct {
	EncryptedEmail        string
	EncryptedUserActivity string
	EncryptedUserAgent    string
}