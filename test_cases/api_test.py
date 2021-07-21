import requests
import json

#res = json.loads(requests.post('http://127.0.0.1:5000/api/auth/signup', data={'username': 'NeilP', 'password': 'abcdefg', 'email': 'neilp235094@gmail.com'}).content.decode())

res = json.loads(requests.post('http://127.0.0.1:5000/api/auth/token', data={'username': 'NeilP', 'password': 'abcdefg'}).content.decode())

print("Login :", res)

if res["error"] == "0":
    headers = {'TOKEN': res['token'], 'Referer': 'http://127.0.0.1:5000/api/wel'}
    res = json.loads(requests.post('http://127.0.0.1:5000/api/scans/add', headers=headers, files={'image': open('images/scan.jfif', 'rb')}).content.decode())
    print("Welcome :", res)

