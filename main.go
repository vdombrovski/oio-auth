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
    "log"
    "encoding/json"
    "math/rand"
    "time"
    "errors"
    "oioiam/oio"
    "oioiam/keystore"
    "golang.org/x/crypto/pbkdf2"
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
    Password *string `json:"password"`
}

type key struct {
    Project *string `json:"project"`
    User *string `json:"user"`
    Access *string `json:"access"`
    Secret *string `json:"secret"`
}

type httpIface struct {
    PC *oio.ProxyClient
    KS *keystore.KeyStore
    // TODO: Store in memcached
    authTokens []string
}

func makeHTTPIface() *httpIface {
    // openssl genrsa -des3 -out private.pem 2048
    ks, err := keystore.MakeKeyStore("/tmp/private.pem", "testytest")
    if err != nil {
        log.Fatal(err)
    }
    return &httpIface{
        PC: oio.MakeProxyClient("http://10.10.10.11:6006", "OPENIO"),
        KS: ks,
    }
}

func main() {
    hc := makeHTTPIface()
    // Administration interface
    http.HandleFunc("/api/v1/auth", hc.authHandler)
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
    err = json.Unmarshal(body, into)
    if err != nil {
        return err
    }
    return nil
}

func (hc *httpIface) authHandler(w http.ResponseWriter, req *http.Request) {
    switch req.Method {
        case "POST":
            ph := ""
            u := user{Project: &ph}
            hc.decode(req, &u)
            if u.Project == nil || u.User == nil || u.Password == nil  {
                w.WriteHeader(http.StatusForbidden)
                return
            }
            props, err := hc.PC.ObjectGetProp(hc.rep(*u.Project), hc.rep(*u.User))
            if err != nil {
                // TODO: 503
                w.WriteHeader(http.StatusBadRequest)
                return
            }
            if pwd, ok := props["pwd"]; ok {
                if hc.hashPassword(*u.Password) == pwd {
                    rand.Seed(time.Now().UnixNano())
                    token := make([]byte, 256)
                    rand.Read(token)
                    fmt.Fprintf(w, "{\"token\": \"" + base64.StdEncoding.EncodeToString(token)[:32] + "\"}")
                    return
                }
            }
            // Current user doesn't have any password?
            w.WriteHeader(http.StatusForbidden)
            return
    }
}

func (hc *httpIface) projectHandler(w http.ResponseWriter, req *http.Request) {
    switch req.Method {
        case "GET":
            projects := []project{}

            props, _ := hc.PC.ObjectGetProp("self", "projects")
            for _, data := range props {
                _, proj, err := hc.decodeKeyPair(data)
                if err != nil {
                    // Invalid project encryption format, ignore it
                    continue
                }
                projects = append(projects, project{Project: &proj})
            }
            res, _ := json.Marshal(projects)
            fmt.Fprintf(w, string(res))
            return
        case "POST":
            ph := ""
            var p = project{Project: &ph}
            err := hc.decode(req, &p)
            if err != nil {
                fmt.Println(err)
            }
            if p.Project == nil {
                // MISSING PROJECT
                w.WriteHeader(http.StatusBadRequest)
                return
            }

            err = hc.addIndex("name", *p.Project, "projects")
            if err != nil {
                // Something wrong with indexing layer
                w.WriteHeader(http.StatusBadRequest)
                return
            }

            _ = hc.PC.ContainerCreate(hc.rep(*p.Project))
            // TODO: implement info on containers, encrypt data
            // hc.PC.ObjectCreate(hc.rep(*p.Project), "self")
            // hc.PC.ObjectSetProp(hc.rep(*p.Project), "self", map[string]string{"iam_name": *p.Project})
        case "DELETE":
            ph := ""
            p := project{Project: &ph}
            hc.decode(req, &p)
            if p.Project == nil {
                // MISSING PROJECT / USER
                w.WriteHeader(http.StatusBadRequest)
                return
            }

            // TODO: ROLLBACK if one of the operations fails
            err := hc.PC.ContainerDel(hc.rep(*p.Project))
            if err != nil {
                w.WriteHeader(http.StatusBadRequest)
                return
            }
            err = hc.delIndex(*p.Project, "projects")
            if err != nil {
                w.WriteHeader(http.StatusBadRequest)
                return
            }
    }
}

func (hc *httpIface) userHandler(w http.ResponseWriter, req *http.Request) {
    switch req.Method {
        case "GET":
            ph := ""
            p := project{Project: &ph}
            if p.Project == nil {
                // MISSING PROJECT / USER
                w.WriteHeader(http.StatusBadRequest)
                return
            }
            hc.decode(req, &p)

            users := []user{}
            props, _ := hc.PC.ObjectGetProp("self", "users")
            for _, data := range props {
                proj, usr, err := hc.decodeKeyPair(data)
                if err != nil {
                    // Invalid project encryption format, ignore it
                    continue
                }
                if proj == *p.Project {
                    users = append(users, user{User: &usr})
                }
            }
            res, _ := json.Marshal(users)
            fmt.Fprintf(w, string(res))
        // TODO : implement PUT method for password change
        case "POST":
            ph := ""
            u := user{Project: &ph}
            hc.decode(req, &u)
            if u.Project == nil || u.User == nil || u.Password == nil  {
                // MISSING PROJECT
                w.WriteHeader(http.StatusBadRequest)
                return
            }
            // TODO: return 409 on error
            hc.PC.ObjectCreate(hc.rep(*u.Project), hc.rep(*u.User))
            err := hc.addIndex(*u.Project, *u.User, "users")
            if err != nil {
                // Something wrong with indexing layer
                w.WriteHeader(http.StatusBadRequest)
                return
            }
            // TODO: can this be done at object creation?
            hc.PC.ObjectSetProp(hc.rep(*u.Project), hc.rep(*u.User), map[string]string{
                "pwd": hc.hashPassword(*u.Password),
            })

        case "DELETE":
            ph := ""
            u := user{Project: &ph}
            hc.decode(req, &u)
            if u.Project == nil || u.User == nil {
                // MISSING PROJECT / USER
                w.WriteHeader(http.StatusBadRequest)
                return
            }
            // TODO: implement rollback
            err := hc.PC.ObjectDel(hc.rep(*u.Project), hc.rep(*u.User))
            if err != nil {
                w.WriteHeader(http.StatusBadRequest)
                return
            }
            err = hc.delIndex(*u.User, "users")
            if err != nil {
                w.WriteHeader(http.StatusBadRequest)
                return
            }
    }
}

func(hc *httpIface) hashPassword(pwd string) string {
	return base64.StdEncoding.EncodeToString(pbkdf2.Key([]byte(pwd), seed, 10000, 50, sha256.New))
}

func (hc *httpIface) addIndex(key, value, t string) error {
    data := key + ":" + value
    enc, err := hc.KS.Encrypt(data)
    if err != nil {
        // Something wrong with encryption layer
        return err
    }

    // TODO: consider doing this at init
    _ = hc.PC.ContainerCreate("self")
    _ = hc.PC.ObjectCreate("self", t)
    return hc.PC.ObjectSetProp("self", t, map[string]string{
        hc.rep(data): enc,
    })
}

func (hc *httpIface) delIndex(index, t string) error {
    return hc.PC.ObjectDelProp("self", t, hc.rep(index))
}

func (hc *httpIface) keyHandler(w http.ResponseWriter, req *http.Request) {
    switch req.Method {
        case "GET":
            ph := ""
            u := user{Project: &ph}
            hc.decode(req, &u)
            res := []key{}
            keys, _ := hc.PC.ObjectGetProp(hc.rep(*u.Project), hc.rep(*u.User))
            for index, keyPair := range(keys) {
                if len(index) != 8 {
                    // Not an access key
                    continue
                }
                access, secret, err := hc.decodeKeyPair(keyPair)
                if err != nil {
                    // Invalid/corrupted key, log and continue
                    continue
                }
                res = append(res, key{
                    Access: &access,
                    Secret: &secret,
                })
            }
            data, _ := json.Marshal(res)
            fmt.Fprintf(w, string(data))

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

            enc, err := hc.KS.Encrypt(access + ":" + secret)
            if err != nil {
                // TODO: Error with encryption layer
                w.WriteHeader(http.StatusBadRequest)
                return
            }

            err = hc.PC.ObjectSetProp(hc.rep(*u.Project), hc.rep(*u.User), map[string]string{
                hc.rep(access): enc,
            })
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
            ph := ""
            k := key{Access: &ph}
            hc.decode(req, &k)
            if k.Access == nil || k.Project == nil || k.User == nil {
                // MISSING ACCESS KEY / PROJECT / USER
                w.WriteHeader(http.StatusBadRequest)
                return
            }
            err := hc.PC.ObjectDelProp(hc.rep(*k.Project), hc.rep(*k.User), hc.rep(*k.Access))
            if err != nil {
                w.WriteHeader(http.StatusBadRequest)
                return
            }
    }
}

func (hc *httpIface) rep(entity string) string {
    return hex.EncodeToString(signSHA256(seed, []byte(entity)))[:8]
}

func (hc *httpIface) decodeKeyPair(key string) (string, string, error) {
    decr, err := hc.KS.Decrypt(key)
    if err != nil {
        return "", "", err
    }
    kp := strings.Split(decr, ":")
    if len(kp) != 2 {
        return "", "", errors.New("token length mismatch")
    }
    return kp[0], kp[1], nil
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

    defer req.Body.Close()
    body, err := ioutil.ReadAll(req.Body)
    if err != nil ||  len(body) != 337 {
        w.WriteHeader(http.StatusBadRequest)
        return
    }

    project := string(body[36:44])
    user := string(body[44:52])

    // TODO: fetch from cache
    data, err := hc.PC.ObjectGetProp(project, user)
    if tokenData, ok := data[hc.rep(string(body[28:60]))]; ok {
        _, secret, err := hc.decodeKeyPair(tokenData)
        if err != nil {
            // Invalid token
            w.WriteHeader(http.StatusForbidden)
            return
        }
        if signV4(string(body[73:253]), secret) != string(body[270:334]) {
            w.WriteHeader(http.StatusForbidden)
            return
        }
        fmt.Fprintf(w, respTpl, project, project, user)
        return
    }
    w.WriteHeader(http.StatusForbidden)
    return
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
