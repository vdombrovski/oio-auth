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
    "encoding/json"
    "oioiam/oio"
    "math/rand"
    "time"
)

var seed = []byte("changeme")
const acVersion = "1"

const respTpl = "{\"token\":{\"roles\":[]," +
"\"project\":{\"domain\":{\"id\":\"\",\"name\":\"\"},\"id\":\"%s\",\"name\":\"%s\"}," +
"\"user\":{\"domain\":{\"id\":\"\",\"name\":\"\"},\"id\":\"\",\"name\":\"%s\"}}}"

type project struct {
    Project *string `json:"project"`
}

type user struct {
    Project *string `json:"project"`
    User *string `json:"user"`
}

type key struct {
    Project *string `json:"project"`
    User *string `json:"user"`
    Access *string `json:"access"`
    Secret *string `json:"secret"`
}

type httpIface struct {
    PC *oio.ProxyClient
}

func makeHTTPIface() *httpIface {
    return &httpIface{
        PC: oio.MakeProxyClient("http://10.10.10.11:6006", "OPENIO"),
    }
}

func main() {
    hc := makeHTTPIface()
    // Administration interface
    http.HandleFunc("/api/v1/users", hc.userHandler)
    http.HandleFunc("/api/v1/projects", hc.projectHandler)
    http.HandleFunc("/api/v1/keys", hc.keyHandler)
    // Multi-cluster sync interface
    http.HandleFunc("/api/v1/sync", hc.cacheSyncHandler)
    // Token validation interface
    http.HandleFunc("/", hc.miscHandler)
    http.HandleFunc("/v2.0/s3tokens", hc.tokenHandler)
    http.ListenAndServe(":8080", nil)
}

func (hc *httpIface) decode(req *http.Request, into interface{}) error {
    defer req.Body.Close()
    body, err := ioutil.ReadAll(req.Body)
    if err != nil {
        return err
    }
    fmt.Println("PROJECT", into)
    err = json.Unmarshal(body, into)
    if err != nil {
        return err
    }
    return nil
}

func (hc *httpIface) projectHandler(w http.ResponseWriter, req *http.Request) {
    switch req.Method {
        case "GET":
            // NOT IMPLEMENTED
            break
        case "POST":
            ph := ""
            var p = project{Project: &ph}
            err := hc.decode(req, &p)
            if err != nil {
                fmt.Println(err)
            }
            if p.Project == nil {
                // MISSING PROJEàCT
                w.WriteHeader(http.StatusBadRequest)
                return
            }
            fmt.Println(hc.rep(*p.Project))
            err = hc.PC.ContainerCreate(hc.rep(*p.Project))
            fmt.Println(err)

        case "DELETE":
            // NOT IMPLEMENTED
            break
    }
}

func (hc *httpIface) userHandler(w http.ResponseWriter, req *http.Request) {
    switch req.Method {
        case "GET":
            // NOT IMPLEMENTED
            break
        case "POST":
            ph := ""
            u := user{Project: &ph}
            hc.decode(req, &u)
            fmt.Println(u)
            if u.Project == nil && u.User == nil {
                // MISSING PROJECT
                w.WriteHeader(http.StatusBadRequest)
                return
            }
            err := hc.PC.ObjectCreate(hc.rep(*u.Project), hc.rep(*u.User))
            fmt.Println(err)
        case "DELETE":
            // NOT IMPLEMENTED
            break
    }
}

func (hc *httpIface) keyHandler(w http.ResponseWriter, req *http.Request) {
    switch req.Method {
        case "GET":
            // NOT IMPLEMENTED
            break
        case "POST":
            ph := ""
            u := user{Project: &ph}
            hc.decode(req, &u)
            if u.Project == nil && u.User == nil {
                // MISSING PROJECT
                w.WriteHeader(http.StatusBadRequest)
                return
            }
            access, secret := hc.newToken(*u.Project, *u.User)
            err := hc.PC.ObjectSet(*u.Project, *u.User, map[string]string{access: secret})
            if err != nil {
                // Something wrong!
                w.WriteHeader(http.StatusBadRequest)
                return
            }
            data, err := json.Marshal(key{
                Project: u.Project,
                User: u.User,
                Access: &access,
                Secret: &secret,
            })
            fmt.Fprintf(w, string(data))
        case "DELETE":
            // NOT IMPLEMENTED
            break
    }
}

func (hc *httpIface) rep(entity string) string {
    return hex.EncodeToString(signSHA256(seed, []byte(entity)))[:8]
}

func (hc *httpIface) newToken(project, user string) (string, string) {
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
    return "oio" + acVersion + hex.EncodeToString(rand1)[:4] + hc.rep(project) + hc.rep(user) + hex.EncodeToString(rand2)[:8],
        hex.EncodeToString(secret)[:32]
}

func (hc *httpIface) cacheSyncHandler(w http.ResponseWriter, req *http.Request) {
    fmt.Println("cache sync")
}


func (hc *httpIface) miscHandler(w http.ResponseWriter, req *http.Request) {
    // TODO: NOT IMPLEMENTED
    fmt.Println("test")
}

func (hc *httpIface) tokenHandler(w http.ResponseWriter, req *http.Request) {
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
