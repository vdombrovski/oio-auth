package main

import (
    "net/http"
    "bytes"
    "fmt"
    "encoding/hex"
    "errors"
)

type proxyClient struct {
    proxyURL string
}

const objBuf = "{\"chunks\":[{\"url\":\"\",\"pos\":\"0\",\"size\":0,\"hash\":\"00000000000000000000000000000000\"}]}"
const globalAcct = "IAM"

func makeProxyClient(url, ns string) *proxyClient {
    return &proxyClient{
        proxyURL: url + "/v3.0/" + ns + "/",
    }
}

func(pc *proxyClient) httpPost(route, data string, hdrs, params map[string]string) error {
    client := &http.Client{}
    paramStr := "?"
    for k, v := range(params) {
        paramStr += k + "=" + v + "&"
    }
    req, _ := http.NewRequest(
        "POST", pc.proxyURL + route + paramStr, bytes.NewBuffer([]byte(data)))
    for k, v := range(hdrs) {
        req.Header.Add(k, v)
    }
    resp, err := client.Do(req)
    if err != nil {
        return err
    } else if resp.StatusCode / 2 == 5 {
        return errors.New("Internal server error")
    }
    return nil
}

func(pc *proxyClient) objectCreate(container, object string) error {
    return pc.httpPost("content/create", objBuf, map[string]string{
        "x-oio-content-meta-length": "0",
        "x-oio-content-meta-policy": "SINGLE",
        "x-oio-content-meta-version": "1",
        "x-oio-content-meta-id": hex.EncodeToString([]byte(container + object)),
    }, map[string]string{"acct": globalAcct, "ref": container, "path": object})
}

func(pc *proxyClient) objectGet(container, object string) (map[string]string, error) {
    // TODO
    return map[string]string{}, nil
}

func(pc *proxyClient) objectSet(container, object, key, value string) error {
    return nil
}

func(pc *proxyClient) containerCreate(container string) error {
    return pc.httpPost("content/create", "", map[string]string{}, map[string]string{
        "acct": globalAcct,
        "ref": container,
    })
}

func main() {
    pc := makeProxyClient("http://10.10.10.11:6006", "OPENIO")
    err := pc.containerCreate("container3")
    err2 := pc.objectCreate("container2", "test2")
    fmt.Println(err, err2)
}
