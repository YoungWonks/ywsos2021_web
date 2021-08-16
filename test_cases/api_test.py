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
    res = json.loads(requests.post('http://127.0.0.1:5000/api/scans', headers=headers,
        json={'position': [20.25, -80.98], 'range': 10}).content.decode())
    for repair in res['repairs']:
        real_url = 'http://127.0.0.1:5000' + repair['url']
        binary = requests.get(real_url).content
        with open('images/read.jfif', 'wb') as f:
            f.write(binary)
        image = cv2.imread('images/read.jfif')
        cv2.imshow("Scans", image)
        print("Location is {}, {}".format(repair['position']['lat'], repair['position']['long']))
        print("Title is {}".format(repair['title']))
        cv2.waitKey()
    print('All of them')
    res = json.loads(requests.post('http://127.0.0.1:5000/api/scans/all', headers=headers,
        json={'position': [20.25, -80.98], 'range': 10}).content.decode())
    for repair in res['repairs']:
        real_url = 'http://127.0.0.1:5000' + repair['url']
        binary = requests.get(real_url).content
        with open('images/read.jfif', 'wb') as f:
            f.write(binary)
        image = cv2.imread('images/read.jfif')
        cv2.imshow("Scans", image)
        print("Location is {}, {}".format(repair['position']['lat'], repair['position']['long']))
        print("Title is {}".format(repair['title']))
        cv2.waitKey()
    print('With vote')
    res = json.loads(requests.post('http://127.0.0.1:5000/api/scans/forum', headers=headers).content.decode())
    for repair in res['repairs']:
        real_url = 'http://127.0.0.1:5000' + repair['url']
        binary = requests.get(real_url).content
        res2 = json.loads(requests.post('http://127.0.0.1:5000/api/vote/voted', headers=headers, json={"scan_id": str(repair['id'])}).content.decode())
        with open('images/read.jfif', 'wb') as f:
            f.write(binary)
        image = cv2.imread('images/read.jfif')
        cv2.imshow("Scans", image)
        print("Location is {}, {}".format(repair['position']['lat'], repair['position']['long']))
        print("Title is {}".format(repair['title']))
        print("Downvote" if res2["voted"] else "Upvote")
        cv2.waitKey()
