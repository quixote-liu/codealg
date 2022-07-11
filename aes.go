package codealg

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
)

func AESECBEncrypt(plaintext, key []byte) ([]byte, error) {
	return nil, nil
}

func AESECBDecrypt(ciphertext, key []byte) ([]byte, error) {
	return nil, nil
}

func AESCBCEncrypt(plaintext, key []byte) ([]byte, error) {
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

func AESCBCDecrypt(ciphertext, key []byte) ([]byte, error) {
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

func GenAESKey() string {
	key := make([]byte, 16)

	// TODO: generate aes key

	return string(key)
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
