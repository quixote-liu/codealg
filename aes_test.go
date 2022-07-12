package codealg

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenAesRandomKey(t *testing.T) {
	key1 := GenAesRandomKey()
	assert.NotEqual(t, "", key1)
	key2 := GenAesRandomKey()
	assert.NotEqual(t, key1, key2)
}

func TestGenAESKey(t *testing.T) {
	key1 := GenAesKey("hello, world")
	assert.NotEqual(t, "", key1)
	key2 := GenAesKey("hello, world")
	assert.Equal(t, key1, key2)
}

func TestAesCBCEncrypt(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		plain   string
		wantErr bool
	}{
		{"should return err with empty key", "", "hello, world", true},
		{"should return err with incorrect key", "insdfa", "hello, world", true},
		{"should pass  with correct key", GenAesRandomKey(), "hello, world", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ciphertext, err := AesCBCEncrypt([]byte(tt.plain), []byte(tt.key))
			if tt.wantErr && err != nil {
				return
			}

			actual, _ := AesCBCDecrypt(ciphertext, []byte(tt.key))
			assert.Equal(t, tt.plain, string(actual))
		})
	}
}

func TestAesCBCDecrypt(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		plain   string
		wantErr bool
	}{
		{"should return err with empty key", "", "hello, world", true},
		{"should return err with incorrect key", "insdfa", "hello, world", true},
		{"should pass  with correct key", GenAesRandomKey(), "hello, world", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ciphertext, _ := AesCBCEncrypt([]byte(tt.plain), []byte(tt.key))
			actual, err := AesCBCDecrypt(ciphertext, []byte(tt.key))
			if tt.wantErr && err != nil {
				return
			}
			assert.Equal(t, tt.plain, string(actual))
		})
	}
}

func TestAesECBEncrypt(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		plain   string
		wantErr bool
	}{
		{"should return err with empty key", "", "hello, world", true},
		{"should return err with incorrect key", "insdfa", "hello, world", true},
		{"should pass  with correct key", GenAesRandomKey(), "hello, world", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ciphertext, err := AesECBEncrypt([]byte(tt.plain), []byte(tt.key))
			if tt.wantErr && err != nil {
				return
			}

			actual, _ := AesECBDecrypt(ciphertext, []byte(tt.key))
			assert.Equal(t, tt.plain, string(actual))
		})
	}
}

func TestAesECBDecrypt(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		plain   string
		wantErr bool
	}{
		{"should return err with empty key", "", "hello, world", true},
		{"should return err with incorrect key", "insdfa", "hello, world", true},
		{"should pass  with correct key", GenAesRandomKey(), "hello, world", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ciphertext, _ := AesECBEncrypt([]byte(tt.plain), []byte(tt.key))
			actual, err := AesECBDecrypt(ciphertext, []byte(tt.key))
			if tt.wantErr && err != nil {
				return
			}
			assert.Equal(t, tt.plain, string(actual))
		})
	}
}

func TestAesCFBEncrypt(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		plain   string
		wantErr bool
	}{
		{"should return err with empty key", "", "hello, world", true},
		{"should return err with incorrect key", "insdfa", "hello, world", true},
		{"should pass  with correct key", GenAesRandomKey(), "hello, world", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ciphertext, err := AesCFBEncrypt([]byte(tt.plain), []byte(tt.key))
			if tt.wantErr && err != nil {
				return
			}

			actual, _ := AesCFBDecrypt(ciphertext, []byte(tt.key))
			assert.Equal(t, tt.plain, string(actual))
		})
	}
}

func TestAesCFBDecrypt(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		plain   string
		wantErr bool
	}{
		{"should return err with empty key", "", "hello, world", true},
		{"should return err with incorrect key", "insdfa", "hello, world", true},
		{"should pass  with correct key", GenAesRandomKey(), "hello, world", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ciphertext, _ := AesCFBEncrypt([]byte(tt.plain), []byte(tt.key))
			actual, err := AesCFBDecrypt(ciphertext, []byte(tt.key))
			if tt.wantErr && err != nil {
				return
			}
			assert.Equal(t, tt.plain, string(actual))
		})
	}
}
