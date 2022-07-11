package codealg

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMarshalAndParsePublicKey(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	assert.Nil(t, err)

	priValues, err := marshalPrivateKey(privateKey)
	assert.Nil(t, err)
	priKey, err := parsePrivateKey(priValues)
	assert.Nil(t, err)
	assert.Equal(t, privateKey, priKey)
}

func TestRSAGenKey(t *testing.T) {
	priv, pub, err := GenRSAKey(1024)
	assert.Nil(t, err)
	// fmt.Println("private key: ", string(priv))
	// fmt.Println("public key:", string(pub))

	prikey, err := parsePrivateKey(priv)
	assert.Nil(t, err)
	assert.NotNil(t, prikey)

	pubkey, err := parsePublicKey(pub)
	assert.Nil(t, err)
	assert.NotNil(t, pubkey)
}

func TestOAPEEncryptAndDecrypt(t *testing.T) {
	prikey, pubkey, err := GenRSAKey(2048)
	assert.Nil(t, err)

	plaintext := []byte("hello, this is plain, we will test the encryption and decryption of OAEP")

	ciphertext, err := EncryptOAEP(plaintext, pubkey)
	assert.Nil(t, err)

	actual, err := DecryptOAEP(ciphertext, prikey)
	assert.Nil(t, err)

	assert.Equal(t, plaintext, actual)
}

func TestEncryptAndDecryptOfPKCS1V15(t *testing.T) {
	prikey, pubkey, err := GenRSAKey(1024)
	assert.Nil(t, err)

	plaintext := []byte("hello, this is plain, we will test the encryption and decryption of PKCS1V15")

	ciphertext, err := EncryptPKCS1v15(plaintext, pubkey)
	assert.Nil(t, err)

	actual, err := DecryptPKCS1v15(ciphertext, prikey)
	assert.Nil(t, err)

	assert.Equal(t, plaintext, actual)
}
