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
    "flag"
    "os"
    "encoding/json"
    "math/rand"
    "time"
    "errors"
    "regexp"
    "kortech.de/oio-iam/oio"
    "kortech.de/oio-iam/keystore"
    "kortech.de/oio-iam/util"
    "golang.org/x/crypto/pbkdf2"
    "github.com/bradfitz/gomemcache/memcache"
    "gopkg.in/yaml.v3"
)

var seed = []byte("changeme")
var tokenExpires = int32(86400)

const respTpl = "{\"token\":{\"roles\":[]," +
"\"project\":{\"domain\":{\"id\":\"\",\"name\":\"\"},\"id\":\"%s\",\"name\":\"%s\"}," +
"\"user\":{\"domain\":{\"id\":\"\",\"name\":\"\"},\"id\":\"%s\",\"name\":\"%s\"}}}"

type project struct {
    Project string `json:"project"`
}

type user struct {
    Project string `json:"project"`
    User string `json:"user"`
    Password string `json:"password"`
    Role string `json:"role"`
}

type key struct {
    Project string `json:"project"`
    User string `json:"user"`
    Access string `json:"access"`
    Secret string `json:"secret"`
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

type LocalCache struct {
    Cache map[string]*memcache.Item
}

func MakeLocalCache() *LocalCache {
    return &LocalCache{Cache: map[string]*memcache.Item{}}
}

func (lc *LocalCache) Get(key string) (*memcache.Item, error) {
    if item, ok := lc.Cache[key]; ok {
        return item, nil
    }
    return nil, errors.New("No such key")
}

func (lc *LocalCache) Set(item *memcache.Item) error {
    lc.Cache[item.Key] = item
    return nil
}

func (lc *LocalCache) Touch(key string, seconds int32) error {
    // NOOP here
    return nil
}


func makeHTTPIface(conf Configuration) *httpIface {
    iface := httpIface{
        PC: oio.MakeProxyClient(conf.Backend.ProxyURL, conf.Backend.Namespace),
        AC: oio.MakeAccountClient(conf.Backend.AccountURL, conf.Backend.Namespace),
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
    
    if conf.Encryption.Type == "AES" {
        if len(conf.Encryption.AESKey) != 32 {
            log.Fatalln("FATAL: AES key needs to be 32 bytes")
        }
        iface.KS = keystore.MakeAESStore("", conf.Encryption.AESKey)
    /* } else if conf.Encryption.Type == "RSA" {
        var err error
        // openssl genrsa -des3 -out private.pem 2048
        iface.KS, err = keystore.RSAKeystore(conf.Encryption.RSAKeyFile, conf.Encryption.RSAKeyPassword)
        if err != nil {
            log.Fatal(err)
        }
    */
    } else {
        log.Fatalln("FATAL: Invalid encryption type, must be in AES")
    }
    
    if conf.Cache.Enabled {
        if len(conf.Cache.Servers) < 1 {
            log.Fatalln("FATAL: memcached cache is enabled but no servers were provided")
        }
        iface.Cache = memcache.New(strings.Split(conf.Cache.Servers, ",")...)
    } else {
        iface.Cache = MakeLocalCache()
    }
    
    return &iface
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
            Project: usrStr[0],
            User: usrStr[1],
            Role: usrStr[2],
        }
        isAdmin := userData.Role != "admin"
        // Super users have all privileges
        if userData.Project == "root" {
            return true
        }
        // Action requires admmin
        if adminRequired && !isAdmin {
            return false
        }
        // Target project is not user's current project
        if proj != "" && (userData.Project != proj) {
            return false
        }
        // Target user is not current user (overriden by project admin)
        if isAdmin || (usr != "" && (userData.User != usr)) {
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

func (hc *httpIface) authHandler(w http.ResponseWriter, req *http.Request) {
    switch req.Method {
        case "POST":
            u := user{Project: ""}
            hc.decodeJSON(req, &u)
            if u.Project == "" || u.User == "" || u.Password == "" {
                // ERR: user, project and password required
                w.WriteHeader(http.StatusBadRequest)
                return
            }
            props, err := hc.PC.ObjectGetProp(hc.rep(u.Project), hc.rep(u.User))
            if err != nil {
                // ERR: BACKEND ERROR
                w.WriteHeader(http.StatusServiceUnavailable)
                return
            }

            if pwd, ok := props["pwd"]; ok {
                if cipher, ok := props["self"]; ok && hc.hashPassword(u.Password) == pwd {
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
                    projects = append(projects, project{Project: proj})
                } else {
                    // TODO: Log integrity error: project without name
                    continue
                }
            }
            res, _ := json.Marshal(projects)
            fmt.Fprintf(w, string(res))
            return
        case "POST":
            var p = project{}
            err := hc.decodeJSON(req, &p)
            if err != nil {
                fmt.Println(err)
            }
            if p.Project == "" {
                log.Println("Failed to create project; missing project")
                w.WriteHeader(http.StatusBadRequest)
                return
            }

            // RBAC: Only superusers can create projects
            if !hc.authorize("root", "", xAuthToken, true) {
                w.WriteHeader(http.StatusForbidden)
                return
            }

            if _, err := hc.PC.ContainerGetProps(hc.rep(p.Project)); err == nil {
                log.Println("Failed to create project: already exists", p.Project)
                w.WriteHeader(http.StatusConflict)
                return
            }

            // TODO: handle these errors
            enc, _ := hc.KS.Encrypt(p.Project)
            _ = hc.PC.ContainerCreate(hc.rep(p.Project), map[string]string{
                "self": enc,
            })
        case "DELETE":
            p := project{Project: ""}
            hc.decodeJSON(req, &p)
            if p.Project == "" {
                // MISSING PROJECT / USER
                w.WriteHeader(http.StatusBadRequest)
                return
            }

            // RBAC: Project admins can remove their project
            if !hc.authorize(p.Project, "", xAuthToken, true) {
                w.WriteHeader(http.StatusForbidden)
                return
            }

            err := hc.PC.ContainerDel(hc.rep(p.Project))
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
            p := project{Project: ""}
            hc.decodeJSON(req, &p)

            if p.Project == "" {
                // MISSING PROJECT / USER
                w.WriteHeader(http.StatusBadRequest)
                return
            }

            // RBAC: Only project admins can view users
            if !hc.authorize(p.Project, "", xAuthToken, true) {
                w.WriteHeader(http.StatusForbidden)
                return
            }

            users := []user{}
            objects, _ := hc.PC.ObjectList(hc.rep(p.Project), true)
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
                    users = append(users, user{User: usrData[1], Role: usrData[2]})
                }
            }
            res, _ := json.Marshal(users)
            fmt.Fprintf(w, string(res))
        case "POST":
            u := user{}
            hc.decodeJSON(req, &u)
            if u.Project == "" || u.User == "" || u.Password == ""  {
                log.Println("Failed to create user; missing project or user or password")
                w.WriteHeader(http.StatusBadRequest)
                return
            }

            // RBAC: Only project admins can add users
            if !hc.authorize(u.Project, "", xAuthToken, true) {
                w.WriteHeader(http.StatusForbidden)
                return
            }

            if u.Role == "" {
                u.Role = "member"
            }
            // TODO: return 409 on error

            enc, _ := hc.KS.Encrypt(u.Project + "/" + u.User + "/" + u.Role)

            if _, err := hc.PC.ObjectGetProp(hc.rep(u.Project), hc.rep(u.User)); err == nil {
                log.Println("Failed to create user: already exists", u.Project, u.User)
                w.WriteHeader(http.StatusConflict)
                return
            }

            hc.PC.ObjectCreate(hc.rep(u.Project), hc.rep(u.User), map[string]string{
                "self": enc,
                "pwd": hc.hashPassword(u.Password),
            })

            if err := hc.AC.PolicyCreateDefault(u.Project, u.User); err != nil {
                log.Println("User was created by policy failed, please check manually", u.Project, u.User, err)
                w.WriteHeader(http.StatusInternalServerError)
                return
            }
        case "PUT":
            u := user{}
            hc.decodeJSON(req, &u)
            if u.Project == "" || u.User == "" || u.Password == ""  {
                // MISSING PROJECT
                log.Println("missing project")
                w.WriteHeader(http.StatusBadRequest)
                return
            }

            // RBAC: Users can change their own password
            if !hc.authorize(u.Project, u.User, xAuthToken, false) {
                w.WriteHeader(http.StatusForbidden)
                return
            }

            hc.PC.ObjectSetProp(hc.rep(u.Project), hc.rep(u.User), map[string]string{
                "pwd": hc.hashPassword(u.Password),
            })
        case "DELETE":
            u := user{}
            hc.decodeJSON(req, &u)
            if u.Project == "" || u.User == "" {
                // MISSING PROJECT / USER
                w.WriteHeader(http.StatusBadRequest)
                return
            }
            // RBAC: Users can self-delete
            if !hc.authorize(u.Project, u.User, xAuthToken, false) {
                w.WriteHeader(http.StatusForbidden)
                return
            }

            if err := hc.AC.PolicyDelete(u.Project, u.User); err != nil {
                log.Println("Policy delete failed, user was not deleted", u.Project, u.User, err)
                w.WriteHeader(http.StatusInternalServerError)
                return
            }

            // TODO: implement rollback
            err := hc.PC.ObjectDel(hc.rep(u.Project), hc.rep(u.User))
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
            u := user{Project: ""}
            hc.decodeJSON(req, &u)
            if u.Project == "" || u.User == "" {
                // MISSING PROJECT
                w.WriteHeader(http.StatusBadRequest)
                return
            }

            // RBAC: Users can see their keys
            if !hc.authorize(u.Project, u.User, xAuthToken, false) {
                w.WriteHeader(http.StatusForbidden)
                return
            }

            res := []key{}
            keys, _ := hc.PC.ObjectGetProp(hc.rep(u.Project), hc.rep(u.User))
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
                accessFull := fmt.Sprintf("%s.%s.%s", u.Project, u.User, access)
                res = append(res, key{
                    Access: accessFull,
                    Secret: secret,
                })
            }
            data, _ := json.Marshal(res)
            fmt.Fprintf(w, string(data))

        case "POST":
            u := user{}
            hc.decodeJSON(req, &u)
            if u.Project == "" && u.User == "" {
                // MISSING PROJECT
                w.WriteHeader(http.StatusBadRequest)
                return
            }

            // RBAC: Users can create their keys
            if !hc.authorize(u.Project, u.User, xAuthToken, false) {
                w.WriteHeader(http.StatusForbidden)
                return
            }

            access, secret := util.NewToken(hc.rep(u.Project), hc.rep(u.User))

            enc, err := hc.KS.Encrypt(access + ":" + secret)
            if err != nil {
                // TODO: Error with encryption layer
                w.WriteHeader(http.StatusBadRequest)
                return
            }

            err = hc.PC.ObjectSetProp(hc.rep(u.Project), hc.rep(u.User), map[string]string{
                hc.rep(access): enc,
            })
            if err != nil {
                // Something wrong!
                w.WriteHeader(http.StatusBadRequest)
                return
            }

            accessFull := fmt.Sprintf("%s.%s.%s", u.Project, u.User, access)

            data, err := json.Marshal(key{
                Access: accessFull,
                Secret: secret,
            })
            fmt.Fprintf(w, string(data))
        case "DELETE":
            k := key{}
            hc.decodeJSON(req, &k)
            if k.Access == "" || k.Project == "" || k.User == "" {
                // MISSING ACCESS KEY / PROJECT / USER
                w.WriteHeader(http.StatusBadRequest)
                return
            }

            // RBAC: Users can revoke their keys
            if !hc.authorize(k.Project, k.User, xAuthToken, false) {
                w.WriteHeader(http.StatusForbidden)
                return
            }

            err := hc.PC.ObjectDelProp(hc.rep(k.Project), hc.rep(k.User), hc.rep(k.Access))
            if err != nil {
                w.WriteHeader(http.StatusBadRequest)
                return
            }
    }
}

type Auth struct {
    Credentials struct {
        Access string `json:"access"`
        Token string `json:"token"`
        Signature string `json:"signature"`
    } `json:"credentials"` 
}

func parseAccess(in string) (string, string, string, error) {
    r := regexp.MustCompile(`(.*\w)\.(.*\w)\.(\w+)`)
    matches := r.FindStringSubmatch(in)
    if len(matches) != 4 {
        return "", "", "", errors.New("Invalid access token format: " + in)
    }
    return matches[1], matches[2], matches[3], nil
}

func (hc *httpIface) tokenHandler(w http.ResponseWriter, req *http.Request) {
    defer hc.timeRequest(time.Now(), hc.Metrics.RtData, hc.Metrics.RqData)
    if req.Method != "POST" {
        w.WriteHeader(http.StatusMethodNotAllowed)
        return
    }
    auth := Auth{}
    if err := json.NewDecoder(req.Body).Decode(&auth); err != nil {
        // TODO: log error
        log.Println("ERROR when validating token", err)
        w.WriteHeader(http.StatusBadRequest)
        return
    }

    project, user, access, err := parseAccess(auth.Credentials.Access)
    if err != nil {
        // TODO: log error
        log.Println("ERROR when validating token", err)
        w.WriteHeader(http.StatusBadRequest)
        return
    }

    tokenData := ""

    if item, err := hc.Cache.Get(access); (err == nil) && (item != nil) {
        tokenData = string(item.Value)
    } else {
        data, err := hc.PC.ObjectGetProp(hc.rep(project), hc.rep(user))
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
    _, secret, err := hc.decodeKeyPair(tokenData)
    if err != nil {
        // Invalid token
        w.WriteHeader(http.StatusForbidden)
        return
    }
    if util.SignV4(auth.Credentials.Token, secret) != auth.Credentials.Signature {
        w.WriteHeader(http.StatusForbidden)
        return
    }
    fmt.Fprintf(w, respTpl, project, project, user, user)
    hc.bumpMetric(hc.Metrics.RqData)
}

type Configuration struct {
    Server struct {
        IP string `yaml:"ip"`
        Port uint `yaml:"port"`
    } `yaml:"server"`
    Backend struct {
        Namespace string `yaml:"namespace"`
        AccountURL string `yaml:"account_url"`
        ProxyURL string `yaml:"proxy_url"`
    } `yaml:"backend"`
    Cache struct {
        Enabled bool `yaml:"enabled"`
        Servers string `yaml:"servers"`
    } `yaml:"cache"`
    Encryption struct {
        Type string `yaml:"type"`
        AESKey string `yaml:"aes_key"`
        // RSAKeyFile string `yaml:"rsa_key_file"`
        // RSAKeyPassword string `yaml:"rsa_key_pass"`
    } `yaml:"encryption"`
}

func readConfig(confFile string) (Configuration, error) {
    conf := Configuration{}
    conf.Server.IP = "localhost"
    conf.Server.Port = 8080
    conf.Backend.Namespace = "OPENIO"
    conf.Backend.AccountURL = "http:/localhost:6009"
    conf.Backend.ProxyURL = "http:/localhost:6006"
    conf.Cache.Enabled = false
    conf.Encryption.Type = "AES"
    conf.Encryption.AESKey = "youneedtochangemeasoonaspossible"
    
    if confFile == "" {
        log.Println("No default configuration file provided; using defaults")
        return conf, nil
    }
    
    f, err := os.Open(confFile)
    if err != nil {
        return conf, err
    }
    
    if err := yaml.NewDecoder(f).Decode(&conf); err != nil {
        return conf, err
    }
    return conf, nil
}

func main() {
    confFile := flag.String("config", "", "Path to configuration file")
    flag.Parse()
    
    conf, err := readConfig(*confFile)
    if err != nil {
        log.Fatalln(err)
    }
    
    hc := makeHTTPIface(conf)

    enc, err := hc.KS.Encrypt("root")
    if err != nil {
        log.Fatal(err)
    }
    
    // Bootstrap default root user if it doesn't exist
    if _, err := hc.PC.ContainerGetProps(hc.rep("root")); err != nil {
        log.Println("Creating default root account")
        if err := hc.PC.ContainerCreate(hc.rep("root"), map[string]string{"self": enc}); err != nil {
            log.Fatalln("FATAL: failed to init account:", err)
        }
        enc, _ = hc.KS.Encrypt("root/root/admin")
        hc.PC.ObjectCreate(hc.rep("root"), hc.rep("root"), map[string]string{
            "pwd": hc.hashPassword("root"),
            "self": enc,
        })
    }
    
    // Administration interface
    http.HandleFunc("/api/v1/auth", hc.authHandler)
    http.HandleFunc("/api/v1/users", hc.userHandler)
    http.HandleFunc("/api/v1/projects", hc.projectHandler)
    http.HandleFunc("/api/v1/keys", hc.keyHandler)
    // Multi-cluster sync interface
    // Monitoring
    http.HandleFunc("/api/v1/metrics", hc.metricHandler)
    http.HandleFunc("/v3/s3tokens", hc.tokenHandler)
    http.ListenAndServe(fmt.Sprintf("%s:%d", conf.Server.IP, conf.Server.Port), nil)
}
