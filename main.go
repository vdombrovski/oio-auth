package main

import (
    "net/http"
    "encoding/base64"
    "io/ioutil"
    "strings"
    "crypto/hmac"
    "crypto/sha256"
    "encoding/hex"
    "fmt"
)

const respTpl = "{\"token\":{\"roles\":[]," +
"\"project\":{\"domain\":{\"id\":\"\",\"name\":\"\"},\"id\":\"%s\",\"name\":\"%s\"}," +
"\"user\":{\"domain\":{\"id\":\"\",\"name\":\"\"},\"id\":\"\",\"name\":\"%s\"}}}"

func main() {
    http.HandleFunc("/", miscHandler)
    http.HandleFunc("/v2.0/s3tokens", tokenHandler)
    http.ListenAndServe(":8080", nil)
}

func miscHandler(w http.ResponseWriter, req *http.Request) {
    fmt.Println("test")
}

func tokenHandler(w http.ResponseWriter, req *http.Request) {
    var projectID = "Project ID whatever"
    var project = "demo"
    var user = "demo"
    var secret = "b1c1348e3a5646d3974c7ac722ac0fdd"

    defer req.Body.Close()
    body, err := ioutil.ReadAll(req.Body)
    if err != nil ||  len(body) != 337 {
        w.WriteHeader(http.StatusBadRequest)
        return
    }
    if signV4(string(body[73:253]), secret) != string(body[270:334]) {
        w.WriteHeader(http.StatusForbidden)
        return
    }
    fmt.Fprintf(w, respTpl, projectID, project, user)
}

func signV4(toSignBytes, secret string) (string) {
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
    signature = signSHA256([]byte("AWS4" + secret), []byte(scope[0]))
    signature = signSHA256(signature, []byte(scope[1]))
    signature = signSHA256(signature, []byte(scope[2]))
    signature = signSHA256(signature, []byte("aws4_request"))
    return hex.EncodeToString(signSHA256(signature, toSign))
}

func signSHA256(key, msg []byte) []byte {
    r := hmac.New(sha256.New, key)
    r.Write(msg)
    return r.Sum(nil)
}
