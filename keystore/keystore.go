package keystore

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"io/ioutil"
    "crypto/x509"
    "encoding/pem"
    "errors"
)

type KeyStore interface {
	Encrypt(msg string) (string, error)
	Decrypt(data string) (string, error)
}

type Store struct {
	key *rsa.PrivateKey
}

func MakeKeyStore(path, pwd string) (*Store, error){
	key, err := loadPrivKey(path, pwd)
	if err != nil {
		return nil, err
	}
	return &Store{key: key}, nil
}

func (ks *Store) Encrypt(msg string) (string, error) {
	rng := rand.Reader
	ct, err := rsa.EncryptOAEP(sha256.New(), rng, &ks.key.PublicKey, []byte(msg), []byte{})
	if err != nil {
		return "", err
	}
    return base64.StdEncoding.EncodeToString(ct), nil
}

func (ks *Store) Decrypt(data string) (string, error) {
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


//
//
// func savePrivKey(key *rsa.PrivateKey, pwd string) ([]byte, error) {
//     block := &pem.Block{
//         Type:  "RSA PRIVATE KEY",
//         Bytes: x509.MarshalPKCS1PrivateKey(key),
//     }
//
//     // Encrypt the pem
//     if pwd == "" {
//         return nil, errors.New("No password provided")
//     }
//     block, err := x509.EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(pwd), x509.PEMCipherAES256)
//     if err != nil {
//         return nil, err
//     }
//     return pem.EncodeToMemory(block), nil
// }
