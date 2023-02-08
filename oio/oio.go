package oio

import (
    "net/http"
    "bytes"
    "encoding/hex"
    "errors"
    "io/ioutil"
    "encoding/json"
    "strings"
    "fmt"
    "log"
)

const bucketPolicy = "{\"Statement\": [{\"Action\": [\"s3:*\"], \"Effect\": \"Allow\", \"Resource\": [\"*\"], \"Sid\": \"FullAccess\"}]}"
const accountPrefix = "AUTH_"

type Proxy interface {
    ContainerCreate(container string, props map[string]string) error
    ContainerDel(container string) error
    ContainerGetProps(container string) (map[string]string, error)
    ObjectCreate(container, object string, props map[string]string) error
    ObjectDel(container, object string) error
    ObjectDelProp(container, object string, prop string) error
    ObjectGetProp(container, object string) (map[string]string, error)
    ObjectList(container string, props bool) ([]Object, error)
    ObjectSetProp(container, object string, props map[string]string) error
}

type Account interface {
    ContainerList() ([]string, error)
    PolicyCreateDefault(project, user string) (error)
    PolicyDelete(project, user string) (error)
}

type Client struct {
    URL string
}

type chunk struct {
    URL string `json:"url"`
    rURL string `json:"real_url"`
    hash string `json:"hash"`
    Pos string `json:"pos"`
    Size int64 `json:"size"`
    Score int64 `json:"score"`
}

type containerList struct {
    Listing [][]interface{} `json:"listing"`
}

type containerProps struct {
    Status int `json:"status"`
    Properties map[string]string `json:"properties"`
}

type objectList struct {
    Objects []Object `json:"objects"`
}

type Object struct {
    Name string `json:"name"`
    Properties map[string]string
}

const globalAcct = "IAM"

func MakeProxyClient(url, ns string) *Client {
    return &Client{
        URL: url + "/v3.0/" + ns + "/",
    }
}

func MakeAccountClient(url, ns string) *Client {
    return &Client{
        URL: url + "/v1.0/",
    }
}

func (ac *Client) ContainerList() ([]string, error) {
    data, err := ac.http("GET", "account/containers", "", nil, map[string]string{"id": globalAcct})
    if err != nil {
        return nil, err
    }
    containers := []string{}
    cntList := containerList{}
    err = json.Unmarshal(data, &cntList)
    if err != nil {
        return nil, err
    }
    for _, c := range(cntList.Listing) {
        containers = append(containers, c[0].(string))
    }
    return containers, nil
}


func (ac *Client) PolicyCreateDefault(project, user string) (error) {
    params := map[string]string{
        "user": fmt.Sprintf("%s:%s", project, user), 
        "account": fmt.Sprintf("%s%s", accountPrefix, project),
    }
    _, err := ac.http("PUT", "iam/put-user-policy", bucketPolicy, nil, params)
    return err
}

func (ac *Client) PolicyDelete(project, user string) (error) {
    params := map[string]string{
        "user": fmt.Sprintf("%s:%s", project, user), 
        "account": fmt.Sprintf("%s%s", accountPrefix, project),
    }
    _, err := ac.http("DELETE", "iam/delete-user-policy", "", nil, params)
    return err
}

func(pc *Client) http(method, url, data string, hdrs, params map[string]string) ([]byte, error) {
    client := &http.Client{}
    paramStr := "?"
    for k, v := range(params) {
        paramStr += k + "=" + v + "&"
    }
    if !strings.HasPrefix(url, "http") {
        url = pc.URL + url
    }

    req, _ := http.NewRequest(
        method, url + paramStr, bytes.NewBuffer([]byte(data)))
    for k, v := range(hdrs) {
        req.Header.Add(k, v)
    }
    resp, err := client.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    body, _ := ioutil.ReadAll(resp.Body)
    if err != nil {
        return body, err
    } else if resp.StatusCode / 100 == 5 {
        return body, errors.New("Internal server error")
    } else if resp.StatusCode / 100 == 4 && resp.StatusCode != 404 {
        return body, errors.New("Bad request")
    }
    return body, nil
}

func(pc *Client) ObjectCreate(container, object string, props map[string]string) error {
    properties, err := json.Marshal(props)
    if err != nil {
        return err
    }
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
        _, err = pc.http("PUT", c.URL, "", map[string]string{
            "X-oio-chunk-meta-full-path": "IAM/" + container + "/" + object + "/1/00000000000000000000000000000000",
            "X-oio-chunk-meta-content-storage-policy": "THREECOPIES", // TODO: configurable policy
            "X-oio-chunk-meta-content-chunk-method": "plain/distance=1,nb_copy=3",
            "X-oio-chunk-meta-chunk-pos": "0",
        }, nil)
        if err != nil {
            // TODO: DELETE ON FAILURE
            return err
        }
    }

    data := "{\"chunks\":" + string(chunkData) + ",\"properties\": " + string(properties) + "}"

    _, err = pc.http("POST", "content/create", data, map[string]string{
        "x-oio-content-meta-length": "0",
        "x-oio-content-meta-policy": "THREECOPIES",
        "x-oio-content-meta-version": "1",
        "x-oio-content-meta-id": hex.EncodeToString([]byte(container + object)),
    }, pc.path(container, object))
    return err
}

func(pc *Client) ObjectDel(container, object string) error {
    _, err := pc.http("POST", "content/delete", "", nil, map[string]string{
        "acct": globalAcct,
        "ref": container,
        "path": object,
    })
    return err
}

func (pc *Client) path(container, object string) map[string]string {
    return map[string]string{"acct": globalAcct, "ref": container, "path": object}
}

func(pc *Client) ObjectGetProp(container, object string) (map[string]string, error) {
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

func(pc *Client) ObjectSetProp(container, object string, props map[string]string) error {
    // data=json.dumps({"properties": {"219021921020129121902":"32932039289328303290"}}))
    propsData, err := json.Marshal(props)
    if err != nil {
        return err
    }
    _, err = pc.http("POST", "content/set_properties", "{\"properties\":" + string(propsData) + "}", nil,
                    pc.path(container, object))
    return nil
}

func(pc *Client) ObjectDelProp(container, object string, prop string) error {
    _, err := pc.http("POST", "content/del_properties", "[\"" + prop + "\"]", nil,
                    pc.path(container, object))
    return err
}

func(pc *Client) ContainerCreate(container string, props map[string]string) error {
    properties, err := json.Marshal(props)
    if err != nil {
        return err
    }
    data := "{\"properties\": " + string(properties) +"}"
    _, err = pc.http("POST", "container/create", data, nil, map[string]string{
        "acct": globalAcct,
        "ref": container,
    })
    return err
}

func (pc *Client) ContainerGetProps(container string) (map[string]string, error) {
    props := containerProps{}
    res, err := pc.http("POST", "container/get_properties", "", nil, map[string]string{
        "acct": globalAcct,
        "ref": container,
    })

    if err != nil {
        return nil, err
    }
    err = json.Unmarshal(res, &props)
    if err != nil {
        return nil, err
    }
    if props.Status == 406 || props.Status == 431 {
        return nil, errors.New("Container not found")
    }
    
    return props.Properties, nil
}

func(pc *Client) ObjectList(container string, props bool) ([]Object, error) {
    doProps := "false"
    if props {
        doProps = "true"
    }
    data, err := pc.http("GET", "container/list", "", nil, map[string]string{
        "acct": globalAcct,
        "ref": container,
        "properties": doProps,
    })

    objList := objectList{}

    err = json.Unmarshal(data, &objList)
    if err != nil {
        return nil,err
    }
    return objList.Objects, err
}

func(pc *Client) ContainerDel(container string) error {
    objects, err := pc.ObjectList(container, false)
    if err != nil {
        return err
    }
    for _, obj := range objects {
        err = pc.ObjectDel(container, obj.Name)
    }
    _, err = pc.http("POST", "container/destroy", "", nil, map[string]string{
        "acct": globalAcct,
        "ref": container,
    })
    return err
}
