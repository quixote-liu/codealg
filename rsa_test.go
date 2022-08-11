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

func TestEncryptOAEP(t *testing.T) {
	privKey, pubKey, err := GenRSAKey(1024)
	assert.Nil(t, err)
	tests := []struct {
		name      string
		plaintext []byte
		wantErr   bool
		pubKey    []byte
	}{
		{"should pass with correct arguments", []byte("hello, world"), false, pubKey},
		{"should respond err with empty plain text", []byte(""), true, pubKey},
		{"should respond err with incorrect public key", []byte("hello, world"), true, []byte("error_public_key")},
		{"should respond err with empty public key", []byte("hello, world"), true, []byte("")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ciphertext, err := EncryptOAEP(tt.plaintext, tt.pubKey)
			if err != nil {
				if tt.wantErr {
					return
				}
				assert.FailNow(t, "want nil error but get error %s", err)
			}
			actual, _ := DecryptOAEP(ciphertext, privKey)
			assert.Equal(t, tt.plaintext, actual)
		})
	}
}

func TestDecryptOAEP(t *testing.T) {
	privKey, pubKey, err := GenRSAKey(1024)
	assert.Nil(t, err)
	ciphertext := func(plaintext []byte) []byte {
		val, _ := EncryptOAEP(plaintext, pubKey)
		return val
	}
	tests := []struct {
		name       string
		ciphertext []byte
		wantErr    bool
		expect     string
		privKey    []byte
	}{
		{"should pass with correct arguments", ciphertext([]byte("hello, world")), false, "hello, world", privKey},
		{"should respond err with empty cipher text", []byte(""), true, "hello, world", privKey},
		{"should respond err with incorrect private key", []byte("hello, world"), true, "hello, world", []byte("error_private_key")},
		{"should respond err with empty private key", ciphertext([]byte("hello, world")), true, "hello, world", []byte("")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual, err := DecryptOAEP(tt.ciphertext, tt.privKey)
			if err != nil {
				if tt.wantErr {
					return
				}
				assert.FailNow(t, "want nil error but get error %s", err)
			}
			assert.Equal(t, tt.expect, string(actual))
		})
	}
}

func TestSignPKCS1v15(t *testing.T) {
	privateKey, publicKey, err := GenRSAKey(RsaKeyBits2048)
	assert.Nil(t, err)
	tests := []struct {
		name    string
		message []byte
		privKey []byte
		wantErr bool
	}{
		{"should pass with correct private key", []byte("hello, world"), privateKey, false},
		{"should return err with incorrect private key", []byte("hello, world"), []byte("error_privateKey"), true},
		{"should pass with empty message", []byte("hello, world"), privateKey, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sig, err := SignPKCS1v15(tt.message, tt.privKey)
			if tt.wantErr {
				assert.NotNil(t, err)
				return
			} else {
				assert.Nil(t, err)
			}
			err = VerifyPKCS1v15(sig, tt.message, publicKey)
			assert.Nil(t, err)
		})
	}
}

func TestVerifyPKCS1v15(t *testing.T) {
	privateKey, publicKey, err := GenRSAKey(RsaKeyBits2048)
	assert.Nil(t, err)
	message := []byte("hello, world")
	sig, err := SignPKCS1v15(message, privateKey)
	assert.Nil(t, err)
	tests := []struct {
		name      string
		signature []byte
		message   []byte
		pubKey    []byte
		wantErr   bool
	}{
		{"should pass with correct message and signature", sig, message, publicKey, false},
		{"should return error with incorrect signature", []byte("error_signature"), message, publicKey, true},
		{"should return error with incorrect message", sig, []byte("error_message"), publicKey, true},
		{"should return error with incorrect public key", sig, message, []byte("error_public_key"), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err = VerifyPKCS1v15(tt.signature, tt.message, tt.pubKey)
			if tt.wantErr {
				assert.NotNil(t, err)
				return
			}
			assert.Nil(t, err)
		})
	}
}

func TestEncryptPKCS1v15(t *testing.T) {
	privKey, pubKey, err := GenRSAKey(1024)
	assert.Nil(t, err)
	tests := []struct {
		name      string
		plaintext []byte
		wantErr   bool
		pubKey    []byte
	}{
		{"should pass with correct arguments", []byte("hello, world"), false, pubKey},
		{"should respond err with empty plain text", []byte(""), true, pubKey},
		{"should respond err with incorrect public key", []byte("hello, world"), true, []byte("error_public_key")},
		{"should respond err with empty public key", []byte("hello, world"), true, []byte("")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ciphertext, err := EncryptPKCS1v15(tt.plaintext, tt.pubKey)
			if err != nil {
				if tt.wantErr {
					return
				}
				assert.FailNow(t, "want nil error but get error %s", err)
			}
			actual, _ := DecryptPKCS1v15(ciphertext, privKey)
			assert.Equal(t, tt.plaintext, actual)
		})
	}
}

func TestDecryptPKCS1v15(t *testing.T) {
	privKey, pubKey, err := GenRSAKey(1024)
	assert.Nil(t, err)
	ciphertext := func(plaintext []byte) []byte {
		val, _ := EncryptPKCS1v15(plaintext, pubKey)
		return val
	}
	tests := []struct {
		name       string
		ciphertext []byte
		wantErr    bool
		expect     string
		privKey    []byte
	}{
		{"should pass with correct arguments", ciphertext([]byte("hello, world")), false, "hello, world", privKey},
		{"should respond err with empty cipher text", []byte(""), true, "hello, world", privKey},
		{"should respond err with incorrect private key", []byte("hello, world"), true, "hello, world", []byte("error_private_key")},
		{"should respond err with empty private key", ciphertext([]byte("hello, world")), true, "hello, world", []byte("")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual, err := DecryptPKCS1v15(tt.ciphertext, tt.privKey)
			if err != nil {
				if tt.wantErr {
					return
				}
				assert.FailNow(t, "want nil error but get error %s", err)
			}
			assert.Equal(t, tt.expect, string(actual))
		})
	}
}

func TestGenerateKey(t *testing.T) {
	privateKey, publicKey, err := GenRSAKey(2048)
	assert.Nil(t, err)
	assert.NotEmpty(t, privateKey)
	assert.NotEmpty(t, publicKey)
	// fmt.Println(string(privateKey))
	// fmt.Println(string(publicKey))
}
