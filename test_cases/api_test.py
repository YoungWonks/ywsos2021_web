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
    res = json.loads(requests.post('http://127.0.0.1:5000/api/auth/signup', data={'username': username, 'password': password, 'email': email}).content.decode())

res = json.loads(requests.post('http://127.0.0.1:5000/api/auth/token', data={'username': username, 'password': password}).content.decode())

print("Login :", res)

if res["error"] == "0":
    headers = {'TOKEN': res['token'], 'Referer': 'http://127.0.0.1:5000/api/wel'}
    res = json.loads(requests.post('http://127.0.0.1:5000/api/wel', headers=headers).content.decode())
    print("Welcome :", res)
    '''res = json.loads(requests.post('http://127.0.0.1:5000/api/scans/add', headers=headers, 
        files={'image': open('images/scan.jfif', 'rb')}, data={'lat': 20.25001, 'long': -80.98001}).content.decode())
    print("Welcome :", res)
    res = json.loads(requests.post('http://127.0.0.1:5000/api/scans/add', headers=headers, 
        files={'image': open('images/scan2.jfif', 'rb')}, data={'lat': 20.25, 'long': -80.98}).content.decode())
    print("Welcome :", res)'''
    res = json.loads(requests.post('http://127.0.0.1:5000/api/scans', headers=headers,
        data={'lat': 20.25, 'long': -80.98, 'range': 10}).content.decode())
    print("Welcome :", res)
    for url in res['urls']:
        real_url = 'http://127.0.0.1:5000' + url
        b = requests.get(real_url).content
        with open('images/read.jfif', 'wb') as f:
            f.write(b)
        image = cv2.imread('images/read.jfif')
        cv2.imshow("Scans", image)
        cv2.waitKey()
