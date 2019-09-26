import requests
import json
import sys


url = "http://localhost:8080"


def dft():
    res = requests.post(url + "/api/v1/projects", data=json.dumps(dict(project="biloute")))
    print(res.__dict__)
    res = requests.post(url + "/api/v1/users", data=json.dumps(dict(project="biloute", user="test")))
    print(res.__dict__)
    res = requests.post(url + "/api/v1/keys", data=json.dumps(dict(project="biloute", user="test")))
    print(res.json())

def delk():
    res = requests.delete(url + "/api/v1/keys", data=json.dumps(dict(project="biloute", user="test", access="oio1505ff4aebb9b76a0ea12cc9e3a91")))
    print(res.json())

def delu():
    res = requests.delete(url + "/api/v1/users", data=json.dumps(dict(project="biloute", user="test")))
    print(res.__dict__)

def delp():
    res = requests.delete(url + "/api/v1/projects", data=json.dumps(dict(project="biloute")))
    print(res.__dict__)

def getk():
    res = requests.get(url + "/api/v1/keys", data=json.dumps(dict(project="biloute", user="test")))
    print(res.json())

def getu():
    res = requests.get(url + "/api/v1/users", data=json.dumps(dict(project="biloute")))
    print(res.json())

dft()
# delp()
#delu()
#delk()
#
# getk()
#getu()


# url = "http://10.10.10.11:6006/v3.0/OPENIO/"
#
# res = requests.post(url + "container/create", params=dict(acct="IAM", ref="container2"))
#
# print(res.__dict__)
#
# # res2 = requests.post(url + "content/prepare", params=dict(acct="IAM", ref="container2", path="object"), data="{\"size\":0}")
# # print(res2.__dict__)
#
#
# bogus_data="{\"chunks\":[{\"url\":\"\",\"pos\":\"0\",\"size\":0,\"hash\":\"00000000000000000000000000000000\"}]}"
#
# res3 = requests.post(url + "content/create", params=dict(acct="IAM", ref="container2", path="object3"), data=bogus_data, headers={
#     "x-oio-content-meta-length": "0",
#     "x-oio-content-meta-policy": "SINGLE",
#     "x-oio-content-meta-version": "1",
#     "x-oio-content-meta-id": "AAAD"})
#
# print(res3.__dict__)
#
# print("\n\nSET/GET\n\n")
#
# # json.dumps([dict(
# #         real_url="",
# #         url="",
# #         hash="a"*32,
# #         pos="0.1",
# #         size=0,
# #     )])
#
# res2 = requests.post(url + "content/set_properties", params=dict(acct="IAM", ref="container2", path="object"),
#     data=json.dumps({"properties": {"219021921020129121902":"32932039289328303290"}}))
# print(res2.__dict__)
#
# res2 = requests.post(url + "content/get_properties", params=dict(acct="IAM", ref="container2", path="object"))
# print(res2.__dict__)
