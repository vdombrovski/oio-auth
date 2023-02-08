package main

import (
	"net/http"
	"fmt"
	"flag"
	"os"
	"time"
	"log"
	"syscall"
	"bytes"
	"strings"
	"io"
	"errors"
	"golang.org/x/term"
	"encoding/json"
)

const AUTH_TOKEN_NAME = "OIO_AUTH_TOKEN"

func usage() {
	fmt.Println("Usage: oio-identity-client [entity] [action] (--opts)")
	fmt.Println(`Available actions:
	* auth login: login and print token
	  usage: export OIO_AUTH_TOKEN=$(oio-identity-client auth login --auth-user root --auth-tenant root)
	* tenant list: list tenants
	* tenant create: create a new tenant
		--tenant
	* tenant delete: deletes a new tenant and all associated users
		--tenant
	* user create: creates a new user inside the tenant
		--tenant
		--user
		(--password): when not provided, will be fetched from stdin
	* user list: lists users inside tenant
		--tenant
	* user delete: deletes a user from the tenant
		--tenant
		--user
	* key create: creates a new key for the user
		--tenant
		--user
	* key list: lists all keys for the user
		--tenant
		--user
	* key delete: deletes a specified access key
		--tenant
		--user
		--access-key
	* help show: prints this help message
	`)
}

type Client struct {
	Endpoint string
	HTTP *http.Client
	Headers map[string]string
}

func (c *Client) HTTPRequest(method, url string, data io.Reader, into interface{}) (err error) {
	req, err := http.NewRequest(method, c.Endpoint + url, data)
	if err != nil {
		return err
	}
	for k, v := range c.Headers {
		req.Header.Set(k, v)
	}
	res, err := c.HTTP.Do(req)
	if err != nil {
	  return err
	}
	if res.StatusCode / 100 != 2 {
	  return errors.New(fmt.Sprintf("Request POST '%s' failed with status code (%d)", url, res.StatusCode))
	}
	defer res.Body.Close()
	if into != nil {
		json.NewDecoder(res.Body).Decode(into)
	}
	return nil
}

func readPassword() string {
	os.Stderr.WriteString("Password: ")
	bytepw, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		log.Fatalln(err)
	}
	return string(bytepw)
}

func (c *Client) Auth(tenant, user, password string) string {
	if tenant == "" || user == "" {
		log.Fatalln("Failed to authenticate: missing tenant/user")
	}
	if password == "" {
		password = readPassword()
	}

	data := map[string]string{
		"project": tenant,
		"user": user,
		"password": password,
	}
	request, err := json.Marshal(data)
	if err != nil {
		log.Fatalln(err)
	}
	response := map[string]string{}

	if err := c.HTTPRequest("POST", "/api/v1/auth", bytes.NewReader(request), &response); err != nil {
		if strings.Contains(err.Error(), "(403)") {
			log.Fatalln("Failed to authenticate: invalid tenant/user/password")
		}
		log.Fatalln(err)
	}
	return response["token"]
}

func main() {
	fs := flag.NewFlagSet("f1", flag.ContinueOnError)
	endpoint := fs.String("endpoint", "http://localhost:35357", "Identity endpoint")
	authTenant := fs.String("auth-tenant", "", "Tenant for authentication")
	authUser := fs.String("auth-user", "", "User for authentication")
	authPassword := fs.String("auth-password", "", "Password for authentication (fetched interactively if not supplied)")

	if len(os.Args) < 3 || (os.Args[1] == "help" && os.Args[2] == "show") {
		usage() 
		return
	}
	entity, action := os.Args[1], os.Args[2]

	data := map[string]*string{}

	switch fmt.Sprintf("%s %s", entity, action) {
		case "key create", "key list", "user delete":
			data["project"] = fs.String("tenant", "", "Tenant")
			data["user"] = fs.String("user", "", "User")
		case "key delete":
			data["project"] = fs.String("tenant", "", "Tenant")
			data["user"] = fs.String("user", "", "User")
			data["access"] = fs.String("access-key", "", "Access key")
		case "tenant create", "tenant delete", "user list":
			data["project"] = fs.String("tenant", "", "Tenant")
		case "tenant list":
		case "user create", "user update":
			data["project"] = fs.String("tenant", "", "Tenant")
			data["user"] = fs.String("user", "", "User")
			data["password"] = fs.String("password", "", "Password (stdin when not provided")
		case "auth login":
		default:
			log.Fatalln("Invalid operation", entity, action)
	}
	url := ""
	method := ""
	listedEntities := map[string]bool{}
	switch entity {
		case "tenant":
			listedEntities["project"] = true
			url = "/api/v1/projects"
		case "user":
			listedEntities["user"] = true
			url = "/api/v1/users"
		case "key":
			listedEntities["access"] = true
			listedEntities["secret"] = true
			url = "/api/v1/keys"
	}
	switch action {
		case "create":
			method = "POST"
		case "list":
			method = "GET"
		case "delete":
			method = "DELETE"
		case "update":
			method = "PUT"
	}

	if err := fs.Parse(os.Args[3:]); err != nil {
		log.Fatalln(err)
	}

	for k, v := range data {
		if k == "password" && *v == "" {
			password := readPassword()
			data[k] = &password
		} else if *v == "" {
			if k == "project" {
				k = "tenant"
			}
			if k == "access" {
				parts := strings.Split(*v, ".")
				data[k] = &parts[len(parts) - 1]
			}
			log.Fatalln("Required option:", "--" + k)
		}
	}

	c := Client{HTTP: &http.Client{Timeout: 5 * time.Second}, Endpoint: *endpoint, Headers: map[string]string{}}
	if os.Getenv(AUTH_TOKEN_NAME) != "" {
		c.Headers["X-Auth-Token"] = os.Getenv(AUTH_TOKEN_NAME)
	} else {
		c.Headers["X-Auth-Token"] = c.Auth(*authTenant, *authUser, *authPassword)
	}
	if entity == "auth" && action == "login" {
		fmt.Println(c.Headers["X-Auth-Token"])
		return
	}

	request, err := json.Marshal(data)
	if err != nil {
		log.Fatalln(err)
	}
	
	if action == "list" {
		response := []map[string]string{}
		if err := c.HTTPRequest(method, url, bytes.NewReader(request), &response); err != nil {
			log.Fatalln("Failed to perform action", err)
		}
		if len(response) == 0 {
			fmt.Println("No results")
		}
		sep := true
		access := ""
		secret := ""
		for _, result := range response {
			for k, v := range result {
				if _, ok := listedEntities[k]; ok {
					if k == "access" {
						access = fmt.Sprintf("aws_access_key_id=%s\n", v)
					} else if k == "secret" {
						secret = fmt.Sprintf("aws_secret_access_key=%s\n", v)
					} else {
						fmt.Println(v)
						sep = false
					}
				}
			}
			if sep {
				fmt.Println(access + secret)
			}
		}
		return
	}
	
	response := map[string]string{} 
	if err := c.HTTPRequest(method, url, bytes.NewReader(request), &response); err != nil {
		log.Fatalln("Failed to perform action", err)
	}
	if action == "create" && entity == "key" {
		fmt.Printf("aws_access_key_id=%s\n", response["access"])
		fmt.Printf("aws_secret_access_key=%s\n", response["secret"])
	} else {
		fmt.Println("Success")
	}
}