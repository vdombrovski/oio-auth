package keystore

import (
	"crypto/aes"
	"crypto/rand"
	"crypto/cipher"
	"encoding/base64"
	"io"
)

type KeyStore interface {
	Encrypt(msg string) (string, error)
	Decrypt(data string) (string, error)
}

type AESStore struct {
	key *[]byte
}

func MakeAESStore(path, pwd string) (*AESStore) {
	// TODO: fetch key from somewhere?
	key := []byte(pwd)
	return &AESStore{
		key : &key,
	}
}

func (ks *AESStore) Encrypt(msg string) (string, error) {

	block, err := aes.NewCipher(*ks.key)
	if err != nil {
		return "", err
	}

	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce = append(nonce, aesgcm.Seal(nil, nonce, []byte(msg), nil)...)

	return base64.StdEncoding.EncodeToString(nonce), nil
}

func (ks *AESStore) Decrypt(msg string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(msg)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(*ks.key)
	if err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	plain, err := aesgcm.Open(nil, data[:12], data[12:len(data)], nil)
	if err != nil {
		return "", err
	}

	return string(plain), nil
}
