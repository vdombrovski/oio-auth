package keystore

import (
	"crypto/aes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/cipher"
	"encoding/base64"
	"os"
	"io"
	"io/ioutil"
    "crypto/x509"
    "encoding/pem"
    "errors"
)

type KeyStore interface {
	Encrypt(msg string) (string, error)
	Decrypt(data string) (string, error)
}

type PlainStore struct {
}
type AESStore struct {
	key *[]byte
}

type RSAStore struct {
	key *rsa.PrivateKey
}

func MakePlainStore(path, pwd string) (*PlainStore) {
	return &PlainStore{}
}

func (ks *PlainStore) Encrypt(msg string) (string, error) {
	return msg, nil
}

func (ks *PlainStore) Decrypt(msg string) (string, error) {
	return msg, nil
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

func MakeRSAStore(path, pwd string) (*RSAStore, error){
	key, err := loadPrivKey(path, pwd)
	if err != nil {
		return nil, err
	}
	return &RSAStore{key: key}, nil
}

func (ks *RSAStore) Encrypt(msg string) (string, error) {
	rng := rand.Reader
	ct, err := rsa.EncryptOAEP(sha256.New(), rng, &ks.key.PublicKey, []byte(msg), []byte{})
	if err != nil {
		return "", err
	}
    return base64.StdEncoding.EncodeToString(ct), nil
}

func (ks *RSAStore) Decrypt(data string) (string, error) {
	ciphertext, _ := base64.StdEncoding.DecodeString(data)
	rng := rand.Reader
	msg, err := rsa.DecryptOAEP(sha256.New(), rng, ks.key, ciphertext, []byte{})
	if err != nil {
		return "", err
	}
	return string(msg), nil
}

func loadPrivKey(filename string, pwd string) (*rsa.PrivateKey, error) {
	file, err := os.Open(filename)
    if err != nil {
        return nil, err
    }
    defer file.Close()

	data, err := ioutil.ReadAll(file)
    if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)

	if block == nil || block.Type != "RSA PRIVATE KEY" {
        return nil, errors.New("failed to decode PEM block")
	}

    bytes, err := x509.DecryptPEMBlock(block, []byte(pwd))
    if err != nil {
        return nil, err
	}
	privKey, err := x509.ParsePKCS1PrivateKey(bytes)
	if err != nil {
        return nil, err
	}
    return privKey, nil
}
