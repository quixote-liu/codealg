package codealg

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// ----------------- OAEP --------------------------------

func EncryptOAEP(plaintext, publickKey []byte) ([]byte, error) {
	pub, err := parsePublicKey(publickKey)
	if err != nil {
		return nil, err
	}
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, plaintext, nil)
}

func DecryptOAEP(ciphertext, privateKey []byte) ([]byte, error) {
	priv, err := parsePrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, ciphertext, nil)
}

// ----------------- PKCS1v15 --------------------------------

func EncryptPKCS1v15(plaintext, publicKey []byte) ([]byte, error) {
	pub, err := parsePublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	return rsa.EncryptPKCS1v15(rand.Reader, pub, plaintext)
}

func DecryptPKCS1v15(ciphertext []byte, privateKey []byte) ([]byte, error) {
	priv, err := parsePrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	return rsa.DecryptPKCS1v15(rand.Reader, priv, ciphertext)
}

// ----------------- common --------------------------------

const (
	RsaKeyBits1024 = 1024
	RsaKeyBits2048 = 2048
	RsaKeyBits4096 = 4096
)

func GenRSAKey(bits int) (privateKey, publicKey []byte, err error) {
	priKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return
	}

	privateKey, err = marshalPrivateKey(priKey)
	if err != nil {
		return
	}

	publicKey, err = marshalPublicKey(&priKey.PublicKey)

	return
}

func marshalPrivateKey(key *rsa.PrivateKey) ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	stream := x509.MarshalPKCS1PrivateKey(key)
	err := pem.Encode(buf, &pem.Block{
		Bytes: stream,
	})
	return buf.Bytes(), err
}

func parsePrivateKey(key []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(key)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func marshalPublicKey(key *rsa.PublicKey) ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	stream := x509.MarshalPKCS1PublicKey(key)
	err := pem.Encode(buf, &pem.Block{
		Bytes: stream,
	})
	return buf.Bytes(), err
}

func parsePublicKey(key []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(key)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing public key")
	}
	return x509.ParsePKCS1PublicKey(block.Bytes)
}
