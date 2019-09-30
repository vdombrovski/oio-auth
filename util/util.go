package util

import(
    "encoding/base64"
    "strings"
    "crypto/hmac"
    "crypto/sha256"
    "encoding/hex"
    "math/rand"
    "time"
)

var acVersion = "1"

func NewToken(projRep, usrRep string) (string, string) {
    // TOKEN SPEC:
    // ACCESS
    // total = 32 bytes
    // oio = static
    // version = 1 byte: token version
    // rand1 = 4 bytes: random data
    // project = 8 bytes: sha256, first 8 bytes
    // user = 8 bytes: sha256, first 8 bytes
    // rand2 = 8 bytes: random data
    // SECRET
    // total = 32 bytes
    // rand1 = 32 bytes: random data

    // Re-seed
    rand.Seed(time.Now().UnixNano())
    rand1 := make([]byte, 32)
    rand2 := make([]byte, 32)
    secret := make([]byte, 32)
    rand.Read(rand1)
    rand.Read(rand2)
    rand.Read(secret)
    return "oio" + acVersion + hex.EncodeToString(rand1)[:4] + projRep + usrRep + hex.EncodeToString(rand2)[:8],
        hex.EncodeToString(secret)[:32]
}

func SignV4(toSignBytes, secret string) (string) {
    toSign, _ := base64.StdEncoding.DecodeString(toSignBytes)
    signature := []byte{}
    parts := strings.Split(string(toSign), "\n")
    if len(parts) != 4 || parts[0] != "AWS4-HMAC-SHA256" {
        return ""
    }
    scope := strings.Split(parts[2], "/")
    if scope[2] != "s3" || scope[3] != "aws4_request" {
        return ""
    }
    signature = SignSHA256([]byte("AWS4" + secret), []byte(scope[0]))
    signature = SignSHA256(signature, []byte(scope[1]))
    signature = SignSHA256(signature, []byte(scope[2]))
    signature = SignSHA256(signature, []byte("aws4_request"))
    return hex.EncodeToString(SignSHA256(signature, toSign))
}

func SignSHA256(key, msg []byte) []byte {
    r := hmac.New(sha256.New, key)
    r.Write(msg)
    return r.Sum(nil)
}
