package codealg

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"io"
	mrand "math/rand"
	"strconv"
	"sync"
	"time"
)

// ----------------- ECB --------------------------------

func AesECBEncrypt(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	length := (len(plaintext) + aes.BlockSize) / aes.BlockSize
	plain := make([]byte, length*aes.BlockSize)
	copy(plain, plaintext)
	pad := byte(len(plain) - len(plaintext))
	for i := len(plaintext); i < len(plain); i++ {
		plain[i] = pad
	}
	encrypted := make([]byte, len(plain))
	blockSize := block.BlockSize()
	for bs, be := 0, blockSize; bs <= len(plaintext); bs, be = bs+blockSize, be+blockSize {
		block.Encrypt(encrypted[bs:be], plain[bs:be])
	}
	return encrypted, nil
}

func AesECBDecrypt(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	decrypted := make([]byte, len(ciphertext))
	blockSize := block.BlockSize()
	for bs, be := 0, blockSize; bs < len(ciphertext); bs, be = bs+blockSize, be+blockSize {
		block.Decrypt(decrypted, ciphertext)
	}
	trim := 0
	if len(decrypted) > 0 {
		trim = len(decrypted) - int(decrypted[len(decrypted)-1])
	}
	return decrypted[:trim], nil
}

// ----------------- CBC --------------------------------

func AesCBCEncrypt(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	originData := pkcs5Padding(plaintext, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])
	crypted := make([]byte, len(originData))
	blockMode.CryptBlocks(crypted, originData)
	return crypted, nil
}

func AesCBCDecrypt(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
	originData := make([]byte, len(ciphertext))
	blockMode.CryptBlocks(originData, ciphertext)
	originData = pkcs5UnPadding(originData)
	return originData, nil
}

func pkcs5Padding(plaintext []byte, blockSize int) []byte {
	padding := blockSize - len(plaintext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(plaintext, padtext...)
}

func pkcs5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

// ----------------- CFB --------------------------------

func AesCFBEncrypt(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	encrypted := make([]byte, aes.BlockSize+len(plaintext))
	iv := encrypted[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(encrypted[aes.BlockSize:], plaintext)
	return encrypted, nil
}

func AesCFBDecrypt(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)
	return ciphertext, nil
}

// ----------------- common --------------------------------

var mu sync.Mutex

func GenAesRandomKey() string {
	mu.Lock()
	defer mu.Unlock()

	random := time.Now().UnixMilli() + mrand.Int63()
	key := strconv.FormatInt(random, 10)
	hmacNew := hmac.New(md5.New, []byte(key))
	_, _ = hmacNew.Write([]byte(key))
	return hex.EncodeToString(hmacNew.Sum([]byte("")))
}

func GenAesKey(key string) string {
	hmacNew := hmac.New(md5.New, []byte(key))
	_, _ = hmacNew.Write([]byte(key))
	return hex.EncodeToString(hmacNew.Sum([]byte("")))
}
