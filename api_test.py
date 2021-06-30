import requests
import json

res = json.loads(requests.post('http://127.0.0.1:5000/api/login', data={'username': 'Neil', 'password': 'abcdefg'}).content.decode())

print(res)

headers = {'TOKEN': res['token'], 'Referer': 'http://127.0.0.1:5000/api/wel'}
res = json.loads(requests.post('http://127.0.0.1:5000/api/wel', headers=headers).content.decode())

print(res)
