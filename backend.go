package main

import (
    "net/http"
    "bytes"
    "fmt"
    "encoding/hex"
    "errors"
    "io/ioutil"
    "encoding/json"
    "strings"
)

type proxyClient struct {
    proxyURL string
}

type chunk struct {
    URL string `json:"url"`
    rURL string `json:"real_url"`
    hash string `json:"hash"`
    Pos string `json:"pos"`
    Size int64 `json:"size"`
    Score int64 `json:"score"`
}

const globalAcct = "IAM"

func makeProxyClient(url, ns string) *proxyClient {
    return &proxyClient{
        proxyURL: url + "/v3.0/" + ns + "/",
    }
}

func(pc *proxyClient) http(method, url, data string, hdrs, params map[string]string) ([]byte, error) {
    client := &http.Client{}
    paramStr := "?"
    for k, v := range(params) {
        paramStr += k + "=" + v + "&"
    }
    if !strings.HasPrefix(url, "http") {
        url = pc.proxyURL + url
    }

    req, _ := http.NewRequest(
        method, url + paramStr, bytes.NewBuffer([]byte(data)))
    for k, v := range(hdrs) {
        req.Header.Add(k, v)
    }
    resp, err := client.Do(req)
    defer resp.Body.Close()
    body, _ := ioutil.ReadAll(resp.Body)
    if err != nil {
        return body, err
    } else if resp.StatusCode / 100 == 5 {
        return body, errors.New("Internal server error")
    } else if resp.StatusCode / 100 == 4 {
        return body, errors.New("Bad request")
    }
    return body, nil
}

func(pc *proxyClient) objectCreate(container, object string) error {
    chunkData, err := pc.http("POST", "content/prepare", "{\"size\":0}", map[string]string{}, pc.path(container, object))
    if err != nil {
        return err
    }
    chunks := []chunk{}
    err = json.Unmarshal(chunkData, &chunks)
    if err != nil {
        return err
    }

    for _, c := range chunks {
        fmt.Println(c.URL)
        _, err = pc.http("PUT", c.URL, "", map[string]string{
            "X-oio-chunk-meta-full-path": "IAM/" + container + "/" + object + "/1/00000000000000000000000000000000",
            "X-oio-chunk-meta-content-storage-policy": "THREECOPIES",
            "X-oio-chunk-meta-content-chunk-method": "plain/distance=1,nb_copy=3",
            "X-oio-chunk-meta-chunk-pos": "0",
        }, nil)
        if err != nil {
            // TODO: DELETE ON FAILURE
            return err
        }
    }

    _, err = pc.http("POST", "content/create", string(chunkData), map[string]string{
        "x-oio-content-meta-length": "0",
        "x-oio-content-meta-policy": "THREECOPIES",
        "x-oio-content-meta-version": "1",
        "x-oio-content-meta-id": hex.EncodeToString([]byte(container + object)),
    }, pc.path(container, object))
    return err
}

func (pc *proxyClient) path(container, object string) map[string]string {
    return map[string]string{"acct": globalAcct, "ref": container, "path": object}
}

func(pc *proxyClient) objectGet(container, object string) (map[string]string, error) {
    // TODO
    var res map[string]string
    body, err := pc.http("POST", "content/get_properties", "", nil, pc.path(container, object))
    if err != nil {
        return nil, err
    }
    err = json.Unmarshal(body[14:len(body) - 1], &res)
    if err != nil {
        return nil, err
    }
    return res, nil
}

func(pc *proxyClient) objectSet(container, object string, props map[string]string) error {
    // data=json.dumps({"properties": {"219021921020129121902":"32932039289328303290"}}))
    propsData, err := json.Marshal(props)
    if err != nil {
        return err
    }
    _, err = pc.http("POST", "content/set_properties", "{\"properties\":" + string(propsData) + "}", nil,
                    pc.path(container, object))
    return nil
}

func(pc *proxyClient) containerCreate(container string) error {
    _, err := pc.http("POST", "container/create", "", nil, map[string]string{
        "acct": globalAcct,
        "ref": container,
    })
    return err
}

func main() {
    pc := makeProxyClient("http://10.10.10.11:6006", "OPENIO")
    err := pc.containerCreate("container2")
    err2 := pc.objectCreate("container2", "test2")
    err3 := pc.objectSet("container2", "test2", map[string]string{"a":"1", "b":"tests"})
    test, err4 := pc.objectGet("container2", "test2")
    fmt.Println(test)
    fmt.Println(err, err2, err3, err4)
}
