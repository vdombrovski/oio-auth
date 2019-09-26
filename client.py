#!/usr/bin/env python3
import requests
import sys
import json


BASE = "http://localhost:8080"

if len(sys.argv) < 3:
    print("Usage TODO")
    sys.exit(1)

method = "get" if sys.argv[2] == "list" else "post" if sys.argv[2] == "create" else "delete"


method = None
if sys.argv[2] == "list":
    method = "get"
elif sys.argv[2] == "create":
    method = "post"
elif sys.argv[2] == "delete":
    method = "delete"

data = dict()
if len(sys.argv) >= 4:
    data['project'] = sys.argv[3]
if len(sys.argv) >= 5:
    data['user'] = sys.argv[4]
if len(sys.argv) == 6:
    data['access'] = sys.argv[5]

res = getattr(requests, method)(BASE + "/api/v1/%ss" % sys.argv[1], data=json.dumps(data))
try:
    print(json.dumps(res.json()))
except Exception:
    if res.status_code == 200:
        print("ok")
    else:
        print("error :'(")
