package main

import (
    "net/http"
    "encoding/base64"
    "io/ioutil"
    "strings"
    "crypto/sha256"
    "sync"
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

type metrics struct {
    sync.Mutex
    RtData *int64 `json:"request_time_data"`
    RtAdmin *int64 `json:"request_time_admin"`
    RqData *int64 `json:"requests_data_total"`
    RqData200 *int64 `json:"requests_data_200"`
    RqData403 *int64 `json:"requests_data_403"`
    RqData400 *int64 `json:"requests_data_400"`
    RqData503 *int64 `json:"requests_data_503"`
    RqAdmin *int64 `json:"requests_admin"`
}

type httpIface struct {
    PC oio.Proxy
    AC oio.Account
    KS keystore.KeyStore
    Cache cache
    Metrics metrics
}

func makeHTTPIface() *httpIface {
    // openssl genrsa -des3 -out private.pem 2048
    // ks, err := keystore.RSAKeystore("/tmp/private.pem", "testytest")
    // if err != nil {
    //     log.Fatal(err)
    // }
    return &httpIface{
        PC: oio.MakeProxyClient("http://10.10.10.11:6006", "OPENIO"),
        AC: oio.MakeAccountClient("http://10.10.10.11:6009", "OPENIO"),
        KS: keystore.MakeAESStore("", "xo3ogaiFaishee1nooJoh5quiehi0aib"),
        Cache: memcache.New("10.10.10.11:6019", "10.10.10.12:6019", "10.10.10.13:6019"),
        Metrics: metrics{
            RtData: new(int64),
            RtAdmin: new(int64),
            RqData: new(int64),
            RqData200: new(int64),
            RqData403: new(int64),
            RqData400: new(int64),
            RqData503: new(int64),
            RqAdmin: new(int64),
        },
    }
}

func main() {
    hc := makeHTTPIface()

    enc, err := hc.KS.Encrypt("root")
    if err != nil {
        log.Fatal(err)
    }
    // Bootstrap default root user
    hc.PC.ContainerCreate(hc.rep("root"), map[string]string{"self": enc})
    enc, _ = hc.KS.Encrypt("root/root/admin")
    hc.PC.ObjectCreate(hc.rep("root"), hc.rep("root"), map[string]string{
        "pwd": hc.hashPassword("root"),
        "self": enc,
    })
    // Administration interface
    http.HandleFunc("/api/v1/auth", hc.authHandler)
    http.HandleFunc("/api/v1/users", hc.userHandler)
    http.HandleFunc("/api/v1/projects", hc.projectHandler)
    http.HandleFunc("/api/v1/keys", hc.keyHandler)
    // Multi-cluster sync interface
    http.HandleFunc("/api/v1/sync", hc.cacheSyncHandler)
    // Monitoring
    http.HandleFunc("/api/v1/metrics", hc.metricHandler)
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

func (hc *httpIface) timeRequest(start time.Time, value *int64, total *int64) {
    // Times request and averages it with the set value
    // Should be deferred to be updated after the total counter
    elapsed := time.Since(start).Nanoseconds() / 1e3
    hc.Metrics.Lock()
    if *value >= 0 && *total > 0 {
        *value = (*value * (*total -1) + elapsed) / *total
    } else {
        *value = *total
    }
    hc.Metrics.Unlock()
}

func (hc *httpIface) bumpMetric(value *int64) {
    hc.Metrics.Lock()
    *value ++
    hc.Metrics.Unlock()
}

func (hc *httpIface) authorize(proj, usr, token string, adminRequired bool) bool {
    if item, err := hc.Cache.Get(token); err == nil && item != nil {
        hc.Cache.Touch(token, tokenExpires)
        data, err := hc.KS.Decrypt(string(item.Value))
        if err != nil {
            fmt.Println("encryption backend error")
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

func (hc *httpIface) metricHandler(w http.ResponseWriter, req *http.Request) {
    // Note: possibly a good idea to protect this route
    res, _ := json.Marshal(hc.Metrics)
    fmt.Fprintf(w, string(res))
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
            if u.Project == nil || u.User == nil || u.Password == nil {
                // ERR: user, project and password required
                w.WriteHeader(http.StatusBadRequest)
                return
            }
            props, err := hc.PC.ObjectGetProp(hc.rep(*u.Project), hc.rep(*u.User))
            if err != nil {
                // ERR: BACKEND ERROR
                w.WriteHeader(http.StatusServiceUnavailable)
                return
            }

            if pwd, ok := props["pwd"]; ok {
                if cipher, ok := props["self"]; ok && hc.hashPassword(*u.Password) == pwd {
                    rand.Seed(time.Now().UnixNano())
                    token := make([]byte, 256)
                    rand.Read(token)
                    tokenStr := base64.StdEncoding.EncodeToString(token)[:32]
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
            containers, err := hc.AC.ContainerList()
            if err != nil {
                // TODO: 503, account backend error
                fmt.Println(err)
                w.WriteHeader(http.StatusServiceUnavailable)
                return
            }
            for _, cnt := range(containers) {
                props, err := hc.PC.ContainerGetProps(cnt)
                if err != nil {
                    // TODO: log error with container
                    continue
                }
                if nameEnc, ok := props["self"]; ok {
                    proj, err := hc.KS.Decrypt(nameEnc)
                    if err != nil {
                        // Invalid project encryption format, ignore it
                        continue
                    }
                    projects = append(projects, project{Project: &proj})
                } else {
                    // TODO: Log integrity error: project without name
                    continue
                }
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

            // TODO: handle these errorss
            enc, _ := hc.KS.Encrypt(*p.Project)
            _ = hc.PC.ContainerCreate(hc.rep(*p.Project), map[string]string{
                "self": enc,
            })
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

            err := hc.PC.ContainerDel(hc.rep(*p.Project))
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
            objects, _ := hc.PC.ObjectList(hc.rep(*p.Project), true)
            for _, obj := range objects {
                if usrStr, ok := obj.Properties["self"]; ok {
                    decr, err := hc.KS.Decrypt(usrStr)
                    if err != nil {
                        // Encryption backend error, continue
                        continue
                    }
                    usrData := strings.Split(decr, "/")
                    if len(usrData) != 3 {
                        // Invalid userdata encoding
                        continue
                    }
                    users = append(users, user{User: &usrData[1], Role: &usrData[2]})
                }
            }
            res, _ := json.Marshal(users)
            fmt.Fprintf(w, string(res))
        case "POST":
            ph := ""
            u := user{Project: &ph}
            hc.decodeJSON(req, &u)
            if u.Project == nil || u.User == nil || u.Password == nil  {
                // ERR: MISSING PROJECT/User/Password
                w.WriteHeader(http.StatusBadRequest)
                return
            }

            // RBAC: Only project admins can add users
            if !hc.authorize(*u.Project, "", xAuthToken, true) {
                w.WriteHeader(http.StatusForbidden)
                return
            }

            if u.Role == nil {
                *u.Role = "member"
            }
            // TODO: return 409 on error

            enc, _ := hc.KS.Encrypt(*u.Project + "/" + *u.User + "/" + *u.Role)

            hc.PC.ObjectCreate(hc.rep(*u.Project), hc.rep(*u.User), map[string]string{
                "self": enc,
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
            // err = hc.delIndex(*u.User, "users")
            // if err != nil {
            //     w.WriteHeader(http.StatusBadRequest)
            //     return
            // }
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
    defer hc.timeRequest(time.Now(), hc.Metrics.RtData, hc.Metrics.RqData)
    defer req.Body.Close()
    body, err := ioutil.ReadAll(req.Body)
    if err != nil ||  len(body) != 337 {
        w.WriteHeader(http.StatusBadRequest)
        return
    }

    project := string(body[36:44])
    user := string(body[44:52])
    access := string(body[28:60])
    tokenData := ""

    if item, err := hc.Cache.Get(access); (err == nil) && (item != nil) {
        tokenData = string(item.Value)
    } else {
        data, err := hc.PC.ObjectGetProp(project, user)
        if err != nil {
            // OIO backend error?
            // TODO: 503
            w.WriteHeader(http.StatusForbidden)
            return
        }
        if token, ok := data[hc.rep(access)]; ok {
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
    hc.bumpMetric(hc.Metrics.RqData)
}
