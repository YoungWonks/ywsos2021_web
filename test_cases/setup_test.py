import requests
import json
import sys
import cv2

if len(sys.argv) < 3:
    raise ValueError("Please provide the username and password")

username = sys.argv[1]
password = sys.argv[2]

if len(sys.argv) == 4:
    email = sys.argv[3]
    res = json.loads(requests.post('http://127.0.0.1:5000/api/auth/signup', json={'username': username, 'password': password, 'email': email}).content.decode())

res = json.loads(requests.post('http://127.0.0.1:5000/api/auth/token', json={'username': username, 'password': password}).content.decode())

print("Login :", res)

if res["error"] == "0":
    headers = {'TOKEN': res['token'], 'Referer': 'http://127.0.0.1:5000/api/wel'}
    res = json.loads(requests.post('http://127.0.0.1:5000/api/wel', headers=headers).content.decode())
    print("Welcome :", res)
    res = json.loads(requests.post('http://127.0.0.1:5000/api/scans/upload', headers=headers, files={'image': open('images/scan.jfif', 'rb')}).content.decode())
    res = json.loads(requests.post('http://127.0.0.1:5000/api/scans/add', headers=headers,
        json={'position': [20.25001, -80.98001], 'title': 'Beach', 'filename': res['filename']}).content.decode())
    print("Welcome :", res)
    res = json.loads(requests.post('http://127.0.0.1:5000/api/scans/upload', headers=headers, files={'image': open('images/scan2.jfif', 'rb')}).content.decode())
    res = json.loads(requests.post('http://127.0.0.1:5000/api/scans/add', headers=headers,
        json={'position': [20.25, -80.98], 'title': 'Crack in sidewalk', 'filename': res['filename']}).content.decode())
    print("Welcome :", res)
    res = json.loads(requests.post('http://127.0.0.1:5000/api/scans', headers=headers,
        json={'position': [20.25, -80.98], 'range': 1}).content.decode())
    print("Welcome :", res)
    res = json.loads(requests.post('http://127.0.0.1:5000/api/vote/voting', headers=headers, 
        json={'scan_id': res['repairs'][1]['id']}).content.decode())
    print("Welcome :", res)
