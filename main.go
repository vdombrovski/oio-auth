package main

import (
    "net/http"
    "encoding/base64"
    "io/ioutil"
    "strings"
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
    "oioiam/util"
    "golang.org/x/crypto/pbkdf2"
    "github.com/bradfitz/gomemcache/memcache"
)

var seed = []byte("changeme")
var tokenExpires = int32(86400)

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
    Role *string `json:"role"`
}

type key struct {
    Project *string `json:"project"`
    User *string `json:"user"`
    Access *string `json:"access"`
    Secret *string `json:"secret"`
}

type cache interface {
    Get(key string) (item *memcache.Item, err error)
    Set(item *memcache.Item) error
    Touch(key string, seconds int32) error
}

type httpIface struct {
    PC oio.Proxy
    KS keystore.KeyStore
    Cache cache
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
        Cache: memcache.New("10.10.10.11:6019", "10.10.10.12:6019", "10.10.10.13:6019"),
    }
}
//
// func main() {
//      mc :=
//      mc.Set(&memcache.Item{Key: "foo", Value: []byte("my value")})
//
//      it, err := mc.Get("foo")
//      ...
// }

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

func (hc *httpIface) decodeJSON(req *http.Request, into interface{}) error {
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

func (hc *httpIface) authorize(proj, usr, token string, adminRequired bool) bool {
    if item, err := hc.Cache.Get(token); err == nil && item != nil {
        hc.Cache.Touch(token, tokenExpires)
        data, err := hc.KS.Decrypt(string(item.Value))
        if err != nil {
            // Encryption backend error
            return false
        }
        usrStr := strings.Split(data, "/")
        if len(usrStr) != 3 {
            fmt.Println("invalid cache")
            // TODO: handle invalid cache
            return false
        }
        userData := user{
            Project: &usrStr[0],
            User: &usrStr[1],
            Role: &usrStr[2],
        }
        isAdmin := *userData.Role != "admin"
        // Super users have all privileges
        if *userData.Project == "root" {
            return true
        }
        // Action requires admmin
        if adminRequired && !isAdmin {
            return false
        }
        // Target project is not user's current project
        if proj != "" && (*userData.Project != proj) {
            return false
        }
        // Target user is not current user (overriden by project admin)
        if isAdmin || (usr != "" && (*userData.User != usr)) {
            return false
        }
        return true
    }
    return false
}

func (hc *httpIface) hashPassword(pwd string) string {
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

func (hc *httpIface) rep(entity string) string {
    return hex.EncodeToString(util.SignSHA256(seed, []byte(entity)))[:8]
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



func (hc *httpIface) cacheSyncHandler(w http.ResponseWriter, req *http.Request) {
    fmt.Println("cache sync")
}


func (hc *httpIface) miscHandler(w http.ResponseWriter, req *http.Request) {
    // TODO: NOT IMPLEMENTED
    fmt.Println("test")
}

func (hc *httpIface) authHandler(w http.ResponseWriter, req *http.Request) {
    switch req.Method {
        case "POST":
            ph := ""
            u := user{Project: &ph}
            hc.decodeJSON(req, &u)
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
            // TODO: maybe move role to user data to avoid having to perform this request
            role := ""
            userIndex, _ := hc.PC.ObjectGetProp("self", "users")
            for _, data := range userIndex {
                _, usrDataStr, _ := hc.decodeKeyPair(data)
                usrData := strings.Split(usrDataStr, "/")
                if len(usrData) != 2 {
                    continue
                }
                if usrData[0] == *u.User {
                    role = usrData[1]
                    break
                }
            }
            if role == "" {
                // TODO: 503, this role should always be defined
                w.WriteHeader(http.StatusBadRequest)
                return
            }

            if pwd, ok := props["pwd"]; ok {
                if hc.hashPassword(*u.Password) == pwd {
                    rand.Seed(time.Now().UnixNano())
                    token := make([]byte, 256)
                    rand.Read(token)
                    tokenStr := base64.StdEncoding.EncodeToString(token)[:32]
                    // TODO: encryption
                    cipher, err := hc.KS.Encrypt(*u.Project + "/" + *u.User + "/" + role)
                    if err != nil {
                        // Encryption layer error
                        // TODO: 503
                        w.WriteHeader(http.StatusBadRequest)
                        return
                    }
                    hc.Cache.Set(&memcache.Item{
                        Key: tokenStr,
                        Value: []byte(cipher),
                        Expiration: tokenExpires,
                    })
                    fmt.Fprintf(w, "{\"token\": \"" + tokenStr + "\"}")
                    return
                }
            }
            // Current user doesn't have any password?
            w.WriteHeader(http.StatusForbidden)
            return
    }
}

func (hc *httpIface) projectHandler(w http.ResponseWriter, req *http.Request) {
    xAuthToken := req.Header.Get("X-Auth-Token")
    switch req.Method {
        case "GET":
            // RBAC: Only superusers can list projects
            if !hc.authorize("root", "", xAuthToken, true) {
                w.WriteHeader(http.StatusForbidden)
                return
            }
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
            err := hc.decodeJSON(req, &p)
            if err != nil {
                fmt.Println(err)
            }
            if p.Project == nil {
                // MISSING PROJECT
                w.WriteHeader(http.StatusBadRequest)
                return
            }

            // RBAC: Only superusers can create projects
            if !hc.authorize("root", "", xAuthToken, true) {
                w.WriteHeader(http.StatusForbidden)
                return
            }

            err = hc.addIndex("name", *p.Project, "projects")
            if err != nil {
                // Something wrong with indexing layer
                w.WriteHeader(http.StatusBadRequest)
                return
            }

            _ = hc.PC.ContainerCreate(hc.rep(*p.Project))
        case "DELETE":
            ph := ""
            p := project{Project: &ph}
            hc.decodeJSON(req, &p)
            if p.Project == nil {
                // MISSING PROJECT / USER
                w.WriteHeader(http.StatusBadRequest)
                return
            }

            // RBAC: Project admins can remove their project
            if !hc.authorize(*p.Project, "", xAuthToken, true) {
                w.WriteHeader(http.StatusForbidden)
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
    xAuthToken := req.Header.Get("X-Auth-Token")
    switch req.Method {
        case "GET":
            ph := ""
            p := project{Project: &ph}
            hc.decodeJSON(req, &p)

            if p.Project == nil {
                // MISSING PROJECT / USER
                w.WriteHeader(http.StatusBadRequest)
                return
            }

            // RBAC: Only project admins can view users
            if !hc.authorize(*p.Project, "", xAuthToken, true) {
                w.WriteHeader(http.StatusForbidden)
                return
            }

            users := []user{}
            props, _ := hc.PC.ObjectGetProp("self", "users")
            for _, data := range props {
                proj, usrDataStr, err := hc.decodeKeyPair(data)
                usrData := strings.Split(usrDataStr, "/")
                if len(usrData) != 2 {
                    // Invalid user role encoding format, ignore it
                    continue
                }
                if err != nil {
                    // Invalid project encryption format, ignore it
                    continue
                }
                if proj == *p.Project {
                    users = append(users, user{User: &usrData[0], Role: &usrData[1]})
                }
            }
            res, _ := json.Marshal(users)
            fmt.Fprintf(w, string(res))
        case "POST":
            ph := ""
            u := user{Project: &ph}
            hc.decodeJSON(req, &u)
            if u.Project == nil || u.User == nil || u.Password == nil  {
                // MISSING PROJECT
                log.Println("missing project")
                w.WriteHeader(http.StatusBadRequest)
                return
            }

            // RBAC: Only project admins can add users
            if !hc.authorize(*u.Project, "", xAuthToken, true) {
                w.WriteHeader(http.StatusForbidden)
                return
            }

            role := "member"
            if u.Role != nil {
                role = *u.Role
            }
            // TODO: return 409 on error
            hc.PC.ObjectCreate(hc.rep(*u.Project), hc.rep(*u.User))
            err := hc.addIndex(*u.Project, *u.User + "/" + role, "users")
            if err != nil {
                // Something wrong with indexing layer
                w.WriteHeader(http.StatusBadRequest)
                return
            }
            // TODO: can this be directly done at object creation?
            hc.PC.ObjectSetProp(hc.rep(*u.Project), hc.rep(*u.User), map[string]string{
                "pwd": hc.hashPassword(*u.Password),
            })
        case "PUT":
            ph := ""
            u := user{Project: &ph}
            hc.decodeJSON(req, &u)
            if u.Project == nil || u.User == nil || u.Password == nil  {
                // MISSING PROJECT
                log.Println("missing project")
                w.WriteHeader(http.StatusBadRequest)
                return
            }

            // RBAC: Users can change their own password
            if !hc.authorize(*u.Project, *u.User, xAuthToken, false) {
                w.WriteHeader(http.StatusForbidden)
                return
            }

            hc.PC.ObjectSetProp(hc.rep(*u.Project), hc.rep(*u.User), map[string]string{
                "pwd": hc.hashPassword(*u.Password),
            })
        case "DELETE":
            ph := ""
            u := user{Project: &ph}
            hc.decodeJSON(req, &u)
            if u.Project == nil || u.User == nil {
                // MISSING PROJECT / USER
                w.WriteHeader(http.StatusBadRequest)
                return
            }
            // RBAC: Users can self-delete
            if !hc.authorize(*u.Project, *u.User, xAuthToken, false) {
                w.WriteHeader(http.StatusForbidden)
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

func (hc *httpIface) keyHandler(w http.ResponseWriter, req *http.Request) {
    xAuthToken := req.Header.Get("X-Auth-Token")
    switch req.Method {
        case "GET":
            ph := ""
            u := user{Project: &ph}
            hc.decodeJSON(req, &u)
            if u.Project == nil || u.User == nil {
                // MISSING PROJECT
                w.WriteHeader(http.StatusBadRequest)
                return
            }

            // RBAC: Users can see their keys
            if !hc.authorize(*u.Project, *u.User, xAuthToken, false) {
                w.WriteHeader(http.StatusForbidden)
                return
            }

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
            hc.decodeJSON(req, &u)
            if u.Project == nil && u.User == nil {
                // MISSING PROJECT
                w.WriteHeader(http.StatusBadRequest)
                return
            }

            // RBAC: Users can create their keys
            if !hc.authorize(*u.Project, *u.User, xAuthToken, false) {
                w.WriteHeader(http.StatusForbidden)
                return
            }

            access, secret := util.NewToken(hc.rep(*u.Project), hc.rep(*u.User))

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
            hc.decodeJSON(req, &k)
            if k.Access == nil || k.Project == nil || k.User == nil {
                // MISSING ACCESS KEY / PROJECT / USER
                w.WriteHeader(http.StatusBadRequest)
                return
            }

            // RBAC: Users can revoke their keys
            if !hc.authorize(*k.Project, *k.User, xAuthToken, false) {
                w.WriteHeader(http.StatusForbidden)
                return
            }

            err := hc.PC.ObjectDelProp(hc.rep(*k.Project), hc.rep(*k.User), hc.rep(*k.Access))
            if err != nil {
                w.WriteHeader(http.StatusBadRequest)
                return
            }
    }
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
    access := hc.rep(string(body[28:60]))
    tokenData := ""

    if item, err := hc.Cache.Get(access); (err != nil) && (item != nil) {
        tokenData = string(item.Value)
    } else {
        data, err := hc.PC.ObjectGetProp(project, user)
        if err != nil {
            // OIO backend error?
            // TODO: 503
            w.WriteHeader(http.StatusForbidden)
            return
        }
        if token, ok := data[access]; ok {
            tokenData = token
            hc.Cache.Set(&memcache.Item{Key: access, Value: []byte(tokenData)})
        } else {
            w.WriteHeader(http.StatusForbidden)
            return
        }
    }
    // Note: Asymetric encryption might have a performance impact,
    // consider switching to symmetric encryption for cache (AES256)
    _, secret, err := hc.decodeKeyPair(tokenData)

    if err != nil {
        // Invalid token
        w.WriteHeader(http.StatusForbidden)
        return
    }
    if util.SignV4(string(body[73:253]), secret) != string(body[270:334]) {
        w.WriteHeader(http.StatusForbidden)
        return
    }
    fmt.Fprintf(w, respTpl, project, project, user)
}
