package codealg

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAESCBCEncryptAndDecrypt(t *testing.T) {
	key := "ABCDEFGHIJKLMNOP"
	plaintext := "hello, world"

	ciphertext, err := AESCBCEncrypt([]byte(plaintext), []byte(key))
	assert.Nil(t, err)

	actual, err := AESCBCDecrypt(ciphertext, []byte(key))
	assert.Nil(t, err)

	assert.Equal(t, plaintext, string(actual))
}
