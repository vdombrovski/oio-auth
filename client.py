#!/usr/bin/env python3
import requests
import sys
import json


headers = dict()
try:
    with open("/tmp/.oioiam", "r") as f:
        token = f.read()
        print("loaded token")
        headers["X-Auth-Token"] = token
except Exception:
    pass

BASE = "http://localhost:8080"

if len(sys.argv) < 3:
    print("Usage TODO")
    sys.exit(1)

method = "get" if sys.argv[2] == "list" else "post" if sys.argv[2] == "create" else "delete" if sys.argv[2] == "delete"\
    else "put" if sys.argv[2] == "set-password" else ""

if sys.argv[1] == "login":
    data = dict(
        project=sys.argv[2],
        user=sys.argv[3],
        password=sys.argv[4]
    )
    res = requests.post(BASE + "/api/v1/auth", headers=headers, data=json.dumps(data))
    if res.status_code == 200:
        with open("/tmp/.oioiam", "w+") as f:
            f.write(res.json()['token'])
        print("ok")
    else:
        print("unauthorized")
    sys.exit(0)

data = dict(role="admin")
if len(sys.argv) >= 4:
    data['project'] = sys.argv[3]
if len(sys.argv) >= 5:
    data['user'] = sys.argv[4]
if len(sys.argv) == 6:
    if sys.argv[1] == "user":
        data['password'] = sys.argv[5]
    else:
        data['access'] = sys.argv[5]

res = getattr(requests, method)(BASE + "/api/v1/%ss" % sys.argv[1], headers=headers, data=json.dumps(data))
try:
    print(json.dumps(res.json()))
except Exception:
    if res.status_code == 200:
        print("ok")
    else:
        print(res.status_code)
        print("error :'(")
