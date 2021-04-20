import requests

s = requests.Session()
s.cert = ('/home/tom/Desktop/certs/a.pem', '/home/tom/Desktop/certs/a.key')

response = s.get(url='https://127.0.0.1:5000/')
print(response, response.content)
